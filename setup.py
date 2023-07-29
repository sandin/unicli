# coding: utf-8
import os, re
from setuptools import setup, find_namespace_packages

with open(os.path.join("unicli", "__init__.py"), encoding="utf8") as f:
  version = re.search(r'__version__ = "(.*?)"', f.read()).group(1)

setup(
  name='unicli',
  version=version,
  python_requires='>=3.6',
  description='An interactive command line debugger for unicorn',
  url='http://github.com/sandin/unicli',
  author='lds2012',
  author_email='lds2012@gmail.com',
  license='MIT',
  include_package_data=True, 
  packages=find_namespace_packages(include=['unicli.*', "unicli"]),
  entry_points={
    'console_scripts': [
      'unicli = unicli.cli:main'
    ]
  },
  install_requires='''
capstone==5.0.0.post1
lief==0.13.2
prompt-toolkit==3.0.39
unicorn==2.0.1.post1
pytest==7.4.0
'''.split('\n'),
  zip_safe=False)