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
from utils.file_handler import process_yaml_file


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


class TestProcessYamlFileSafe(unittest.TestCase):
    """Tests that verify process_yaml_file uses yaml.safe_load (CVE-2017-18342 remediation).

    yaml.load() without an explicit Loader can deserialise arbitrary Python objects,
    enabling remote code execution.  The fix replaces it with yaml.safe_load(), which
    only permits standard YAML scalar/mapping/sequence types.
    """

    def _write_yaml(self, content):
        """Helper: write content to a temporary YAML file and return its path."""
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
        tmp.write(content)
        tmp.flush()
        tmp.close()
        return tmp.name

    def tearDown(self):
        # Clean up any leftover temp files (best effort)
        pass

    # ------------------------------------------------------------------
    # Positive / happy-path tests
    # ------------------------------------------------------------------

    def test_returns_dict_for_valid_yaml(self):
        """process_yaml_file correctly parses a simple mapping."""
        path = self._write_yaml("key: value\nnumber: 42\n")
        try:
            result = process_yaml_file(path)
            self.assertIsInstance(result, dict)
            self.assertEqual(result.get('key'), 'value')
            self.assertEqual(result.get('number'), 42)
        finally:
            os.unlink(path)

    def test_returns_list_for_yaml_sequence(self):
        """process_yaml_file handles a top-level list document."""
        path = self._write_yaml("- item1\n- item2\n- item3\n")
        try:
            result = process_yaml_file(path)
            self.assertIsInstance(result, list)
            self.assertEqual(result, ['item1', 'item2', 'item3'])
        finally:
            os.unlink(path)

    def test_nested_structure(self):
        """process_yaml_file handles nested mappings."""
        content = "outer:\n  inner: hello\n  count: 3\n"
        path = self._write_yaml(content)
        try:
            result = process_yaml_file(path)
            self.assertEqual(result['outer']['inner'], 'hello')
            self.assertEqual(result['outer']['count'], 3)
        finally:
            os.unlink(path)

    def test_empty_yaml_returns_none_not_error(self):
        """process_yaml_file on an empty document returns None (safe_load behaviour)."""
        path = self._write_yaml("")
        try:
            result = process_yaml_file(path)
            # safe_load of an empty stream returns None — not an error dict
            self.assertNotIn('error', result if isinstance(result, dict) else {})
        finally:
            os.unlink(path)

    # ------------------------------------------------------------------
    # Security regression tests (CVE-2017-18342)
    # ------------------------------------------------------------------

    def test_unsafe_python_object_tag_is_rejected(self):
        """yaml.safe_load must raise on !!python/object tags (arbitrary code exec vector).

        The classic CVE-2017-18342 payload embeds a !!python/object/apply: tag that
        would trigger OS command execution when loaded with the unsafe yaml.load().
        safe_load() must reject this with a yaml.YAMLError (or return an error dict
        via process_yaml_file's exception handler).
        """
        # Payload that would execute subprocess.check_output(['id']) under yaml.load()
        malicious_yaml = (
            "exploit: !!python/object/apply:subprocess.check_output\n"
            "  args: [['id']]\n"
        )
        path = self._write_yaml(malicious_yaml)
        try:
            result = process_yaml_file(path)
            # The function catches exceptions and returns {'error': ...}
            self.assertIsInstance(result, dict)
            self.assertIn('error', result,
                          "process_yaml_file must return an error dict for unsafe YAML tags, "
                          "not silently execute the embedded constructor.")
        finally:
            os.unlink(path)

    def test_python_object_new_tag_is_rejected(self):
        """!!python/object/new: tags (another RCE vector) must also be rejected."""
        malicious_yaml = (
            "bad: !!python/object/new:os.system\n"
            "  args: ['id']\n"
        )
        path = self._write_yaml(malicious_yaml)
        try:
            result = process_yaml_file(path)
            self.assertIsInstance(result, dict)
            self.assertIn('error', result,
                          "process_yaml_file must reject !!python/object/new: tags.")
        finally:
            os.unlink(path)

    def test_plain_python_tag_is_rejected(self):
        """!!python/object: tags must be rejected by safe_load."""
        malicious_yaml = "payload: !!python/object:os.system\nargs: ['id']\n"
        path = self._write_yaml(malicious_yaml)
        try:
            result = process_yaml_file(path)
            self.assertIsInstance(result, dict)
            self.assertIn('error', result,
                          "process_yaml_file must reject !!python/object: tags.")
        finally:
            os.unlink(path)

    def test_missing_file_returns_error_dict(self):
        """A missing file path must return an error dict, not raise."""
        result = process_yaml_file('/nonexistent/path/to/file.yaml')
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)


if __name__ == '__main__':
    unittest.main()

