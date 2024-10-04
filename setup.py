from setuptools import setup, find_packages

setup(
    name='fir-tool',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'fir=fir.fir:main',  # Ensure this points to your main function
        ],
    },
    install_requires=[
        'cryptography',
        'pyicloud',
        'yara-python',
        # 'libimobiledevice',
        'google-auth',
        'google-api-python-client'  # Add the required Google API client library
    ],
    description='A forensic investigation tool for ethical and security defense use.',
    author='Suleiman Yahaya Garo',
    author_email='garogenius@gmail.com',
    url='https://github.com/yourusername/fir-tool',  # Update to your actual GitHub URL
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6', 
)
