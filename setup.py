import os
from setuptools import setup

def main():
    with open(os.path.join("autocrypt", "__init__.py")) as f:
        for line in f:
            if "__version__" in line.strip():
                version = line.split("=", 1)[1].strip().strip('"')
                break

    with open("README.rst") as f:
        long_desc = f.read()

    setup(
        name='PyAC',
        description='Autocrypt Level 1 implemention using PGPy',
        long_description=long_desc,
        version=version,
        url='https://github.com/juga0/pyac',
        license='MIT license',
        author='juga',
        author_email='juga@riseup.net',
        classifiers=['Development Status :: 3 - Alpha',
                     'Intended Audience :: Developers',
                     'License :: OSI Approved :: MIT License',
                     'Operating System :: OS Independent',
                     'Topic :: Utilities',
                     'Topic :: Communications :: Email',
                     'Intended Audience :: Developers',
                     'Programming Language :: Python :: 3.6'],
        packages=['autocrypt'],
        entry_points='''
            [console_scripts]
            autocrypt=autocrypt.cli:main
        ''',
        install_requires=["click>=6.0", "six", "PGPy>=0.4.1", "emailpgp",
                          "attr"],
        extras_require={
            'dev': ['ipython', 'pyflakes', 'pep8'],
            'test': ['tox', 'pytest'],
            'doc': ['sphinx', 'pylint']
        },
        tests_require=['pytest'],
        zip_safe=False,
    )


if __name__ == '__main__':
    main()
