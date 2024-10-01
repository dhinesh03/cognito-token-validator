from setuptools import setup, find_packages

setup(
    name='cognito_token_validator',
    version='0.1.1',
    packages=find_packages(),
    install_requires=[
        'requests',
        'cachetools',
        'python-jose',
    ],
    author='Dhinesh Kumar Sundaram',
    author_email='dhinesh.gs@gmail.com',
    description='A package for validating AWS Cognito tokens and using them as decorators in Flask routes or standalone Python functions',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/dhinesh03/cognito-token-validator',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
