from setuptools import setup

setup(
    name='iris_misp_module',
    version='0.1',
    packages=['iris_misp_module', 'iris_misp_module.misp_handler'],
    url='https://github.com/dfir-iris/iris-misp-module',
    license='LGPLv3.0',
    author='ekt0, DFIR-IRIS',
    author_email='contact@dfir-iris.org',
    description='IRIS module interfacing MISP with IRIS',
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: LGPLv3",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "setuptools",
        "celery~=4.4.7",
        "pyunpack",
        "pymisp~=2.4.152",
        "Jinja2~=3.0.3"
    ]
)
