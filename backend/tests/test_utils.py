"""
Basic tests for utility functions
"""
import unittest
import sys
import os
import tempfile
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp


class TestDateTimeUtils(unittest.TestCase):
    """Test datetime utility functions"""
    
    def test_get_utc_now(self):
        """Test get_utc_now returns datetime"""
        result = get_utc_now()
        self.assertIsInstance(result, datetime)
    
    def test_get_utc_timestamp(self):
        """Test get_utc_timestamp returns float"""
        result = get_utc_timestamp()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0)
    
    def test_format_utc_datetime_default(self):
        """Test format_utc_datetime with default (current time)"""
        result = format_utc_datetime()
        self.assertIsInstance(result, str)
        # ISO format should contain 'T'
        self.assertIn('T', result)
    
    def test_format_utc_datetime_with_value(self):
        """Test format_utc_datetime with specific datetime"""
        dt = datetime(2023, 12, 25, 15, 30, 45)
        result = format_utc_datetime(dt)
        self.assertIsInstance(result, str)
        self.assertIn('2023', result)
        self.assertIn('12', result)
        self.assertIn('25', result)


class TestStringUtils(unittest.TestCase):
    """Test basic string utilities"""
    
    def test_string_truncation_logic(self):
        """Test basic truncation logic"""
        text = "This is a very long text that should be truncated"
        max_length = 20
        
        if len(text) > max_length:
            truncated = text[:max_length] + '...'
        else:
            truncated = text
        
        self.assertEqual(len(truncated), 23)  # 20 + "..."
        self.assertTrue(truncated.endswith('...'))
    
    def test_file_size_calculation(self):
        """Test file size calculation logic"""
        # Test bytes
        size = 500
        self.assertLess(size, 1024)
        
        # Test KB
        size_kb = 1500
        kb_value = size_kb / 1024.0
        self.assertGreater(kb_value, 1.0)
        self.assertLess(kb_value, 1024.0)


class TestProcessYamlFile(unittest.TestCase):
    """
    Tests for process_yaml_file in utils/file_handler.py.
    Verifies that YAML processing uses safe_load (CVE-2020-1747 remediation).
    """

    def _write_yaml(self, content):
        """Helper: write content to a temporary YAML file and return its path."""
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False
        )
        tmp.write(content)
        tmp.flush()
        tmp.close()
        return tmp.name

    def setUp(self):
        self._tmp_files = []

    def tearDown(self):
        for path in self._tmp_files:
            try:
                os.unlink(path)
            except OSError:
                pass

    def _make_yaml(self, content):
        path = self._write_yaml(content)
        self._tmp_files.append(path)
        return path

    def test_parses_simple_mapping(self):
        """process_yaml_file returns a plain dict for a simple YAML mapping."""
        from utils.file_handler import process_yaml_file

        path = self._make_yaml("name: Alice\nage: 30\n")
        result = process_yaml_file(path)
        self.assertIsInstance(result, dict)
        self.assertEqual(result.get('name'), 'Alice')
        self.assertEqual(result.get('age'), 30)

    def test_parses_nested_mapping(self):
        """process_yaml_file handles nested YAML structures."""
        from utils.file_handler import process_yaml_file

        content = "project:\n  title: Test\n  version: 1\n"
        path = self._make_yaml(content)
        result = process_yaml_file(path)
        self.assertIsInstance(result, dict)
        self.assertIn('project', result)
        self.assertEqual(result['project']['title'], 'Test')

    def test_parses_list(self):
        """process_yaml_file handles top-level YAML lists."""
        from utils.file_handler import process_yaml_file

        path = self._make_yaml("- alpha\n- beta\n- gamma\n")
        result = process_yaml_file(path)
        self.assertIsInstance(result, list)
        self.assertEqual(result, ['alpha', 'beta', 'gamma'])

    def test_empty_file_returns_none_or_dict(self):
        """process_yaml_file handles an empty YAML file without error."""
        from utils.file_handler import process_yaml_file

        path = self._make_yaml("")
        result = process_yaml_file(path)
        # yaml.safe_load on an empty file returns None; the function returns that
        # directly (not an error dict).
        self.assertNotIn('error', result if isinstance(result, dict) else {})

    def test_rejects_python_object_constructor(self):
        """
        CVE-2020-1747: yaml.safe_load must raise an error (not execute code)
        when the YAML payload uses the !!python/object/new constructor.
        process_yaml_file should return an error dict rather than executing
        arbitrary code.
        """
        from utils.file_handler import process_yaml_file

        # This payload exploits the python/object/new constructor via
        # yaml.load() with FullLoader / no loader argument.
        # yaml.safe_load() rejects it with a constructor error.
        malicious_yaml = (
            "exploit: !!python/object/new:subprocess.check_output\n"
            "  args: [['echo', 'pwned']]\n"
        )
        path = self._make_yaml(malicious_yaml)
        result = process_yaml_file(path)
        # safe_load raises yaml.constructor.ConstructorError; the function
        # catches it and returns {'error': ...}.
        self.assertIsInstance(result, dict)
        self.assertIn('error', result,
                      "Expected an error dict when processing a malicious YAML "
                      "payload; got: %r" % result)

    def test_invalid_yaml_returns_error_dict(self):
        """process_yaml_file returns an error dict for malformed YAML."""
        from utils.file_handler import process_yaml_file

        path = self._make_yaml("key: [\n  unclosed\n")
        result = process_yaml_file(path)
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    def test_uses_safe_load_not_full_load(self):
        """
        Confirm that process_yaml_file calls yaml.safe_load, not yaml.load or
        yaml.full_load, by inspecting the source of the function.
        """
        import inspect
        from utils.file_handler import process_yaml_file

        source = inspect.getsource(process_yaml_file)
        self.assertIn('safe_load', source,
                      "process_yaml_file must use yaml.safe_load")
        # Ensure the old unsafe call form is not present
        self.assertNotIn('yaml.load(', source,
                         "process_yaml_file must not use yaml.load() without "
                         "the SafeLoader argument")


if __name__ == '__main__':
    unittest.main()

