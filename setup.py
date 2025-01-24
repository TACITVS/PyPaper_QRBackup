from setuptools import setup, find_packages

setup(
    name="qr_backup_app",
    version="1.0.0",
    description="A Python-based application for encrypting files and text into QR codes.",
    author="Your Name",
    author_email="your.email@example.com",
    packages=find_packages(),
    install_requires=[
        "PyQt5>=5.15.7",
        "pycryptodome>=3.15.0",
        "qrcode[pil]>=7.3.1",
        "pyzbar>=0.1.9",
        "opencv-python>=4.5.5.64",
        "numpy>=1.21.5",
        "pillow>=9.0.1",
        "argon2-cffi>=21.3.0",
    ],
    entry_points={
        "console_scripts": [
            "qr-backup-app=qr_backup_app:main",
        ],
    },
)