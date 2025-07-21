from setuptools import setup, find_packages

setup(
    name="purplest",  
    version="0.1",  
    packages=find_packages(),
    install_requires=[],  
    entry_points={  
        "console_scripts": [
            "purplest=purplest.main:main", 
            "purplest-morse=modules.util_morse:main",
            "purplest-arpspoof=modules.red_arpspoof:main",
        ]
    }
)
