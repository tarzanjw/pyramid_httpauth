import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.txt')) as f:
    README = f.read()
with open(os.path.join(here, 'CHANGES.txt')) as f:
    CHANGES = f.read()

requires = [
    'pyramid',
    ]

setup(name='pyramid_httpauth',
      version='1.0',
      description='pyramid_httpauth',
      long_description=README + '\n\n' + CHANGES,
      classifiers=[
        "Programming Language :: Python",
        "Framework :: Pyramid",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        ],
      author='Tarzan',
      author_email='hoc3010@gmail.com',
      url='https://github.com/tarzanjw/pyramid_httpauth',
      keywords='web wsgi bfg pylons pyramid',
      packages=['pyramid_httpauth', ],
      include_package_data=True,
      zip_safe=False,
      test_suite='pyramid_httpauth',
      install_requires=requires,
      )
