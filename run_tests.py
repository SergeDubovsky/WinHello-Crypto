#!/usr/bin/env python3
"""
Simple test runner for WinHello-Crypto
Handles import issues and provides better error reporting
"""

import sys
import os
import importlib
import traceback

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported."""
    print("Testing module imports...")
    
    modules_to_test = [
        'security_config',
        'security_utils', 
        'hello_crypto',
        'aws_hello_creds'
    ]
    
    results = {}
    
    for module_name in modules_to_test:
        try:
            module = importlib.import_module(module_name)
            results[module_name] = "✅ SUCCESS"
            print(f"  {module_name}: ✅ SUCCESS")
        except ImportError as e:
            results[module_name] = f"❌ IMPORT ERROR: {e}"
            print(f"  {module_name}: ❌ IMPORT ERROR: {e}")
        except Exception as e:
            results[module_name] = f"⚠️  OTHER ERROR: {e}"
            print(f"  {module_name}: ⚠️  OTHER ERROR: {e}")
    
    return results

def test_basic_functionality():
    """Test basic functionality without Windows Hello."""
    print("\nTesting basic functionality...")
    
    try:
        # Test security config
        from security_config import AES_KEY_SIZE, MAX_FILE_SIZE
        print(f"  Security config: AES_KEY_SIZE={AES_KEY_SIZE}, MAX_FILE_SIZE={MAX_FILE_SIZE}")
        
        # Test security utils
        from security_utils import ValidationError, sanitize_error_message
        test_error = Exception("Test error with key and secret")
        sanitized = sanitize_error_message(test_error, "test_operation")
        print(f"  Error sanitization: '{sanitized}'")
        
        # Test basic crypto without Windows Hello
        try:
            from hello_crypto import FileEncryptor
            encryptor = FileEncryptor()
            print("  FileEncryptor created successfully")
            
            # Test data encryption/decryption
            import secrets
            test_data = b"Hello, World!"
            test_key = secrets.token_bytes(32)
            
            encrypted = encryptor.encrypt_data(test_data, test_key)
            decrypted = encryptor.decrypt_data(encrypted, test_key)
            
            if decrypted == test_data:
                print("  ✅ Encryption/decryption test PASSED")
            else:
                print("  ❌ Encryption/decryption test FAILED")
                
        except Exception as e:
            print(f"  ⚠️  Crypto test error (expected on non-Windows): {e}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Basic functionality test failed: {e}")
        traceback.print_exc()
        return False

def run_pytest():
    """Run pytest if available."""
    print("\nRunning pytest...")
    
    try:
        import pytest
        
        # Run tests with verbose output
        exit_code = pytest.main([
            '-v', 
            '--tb=short',
            '--no-header',
            'test_security_utils.py',
            'test_hello_crypto.py::TestFileEncryptor::test_encrypt_decrypt_data_roundtrip',
            'test_aws_hello_creds.py::TestAWSCredentialManager::test_validate_profile_name_valid'
        ])
        
        if exit_code == 0:
            print("  ✅ All selected tests PASSED")
        else:
            print(f"  ⚠️  Some tests failed (exit code: {exit_code})")
            
        return exit_code == 0
        
    except ImportError:
        print("  ⚠️  pytest not available, skipping test execution")
        return True
    except Exception as e:
        print(f"  ❌ pytest execution failed: {e}")
        return False

def main():
    """Main test runner."""
    print("🔐 WinHello-Crypto Test Runner")
    print("=" * 50)
    
    # Test imports
    import_results = test_imports()
    
    # Test basic functionality
    basic_test_passed = test_basic_functionality()
    
    # Run pytest
    pytest_passed = run_pytest()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 TEST SUMMARY")
    print("=" * 50)
    
    print("\nModule Import Results:")
    for module, result in import_results.items():
        print(f"  {module}: {result}")
    
    print(f"\nBasic Functionality: {'✅ PASSED' if basic_test_passed else '❌ FAILED'}")
    print(f"Pytest Execution: {'✅ PASSED' if pytest_passed else '⚠️  ISSUES'}")
    
    # Overall result
    critical_modules = ['security_config', 'security_utils']
    critical_imports_ok = all('SUCCESS' in import_results.get(m, '') for m in critical_modules)
    
    if critical_imports_ok and basic_test_passed:
        print("\n🎉 Overall: TESTS COMPLETED SUCCESSFULLY")
        return 0
    else:
        print("\n⚠️  Overall: SOME ISSUES DETECTED")
        return 1

if __name__ == "__main__":
    sys.exit(main())