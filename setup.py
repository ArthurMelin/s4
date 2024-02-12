from setuptools import setup, find_packages

setup(
   name="s4",
   version="0.1.0",
   author="Arthur Melin",
   url="https://github.com/ArthurMelin/s4",
   python_requires=">=3.12",
   packages=find_packages(),
   install_requires=[
      "boto3",
   ],
   entry_points={
       "console_scripts": [
           "s4 = s4.cli:main"
       ]
   },
)
