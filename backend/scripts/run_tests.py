import subprocess
import sys


def main():
    print("\nRunning TrustLens automated tests...\n")

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-v"],
        check=False
    )

    if result.returncode == 0:
        print("\nAll tests passed!")
    else:
        print("\nSome tests failed.")

    return result.returncode


if __name__ == "__main__":
    sys.exit(main())