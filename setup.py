from setuptools import setup
import sys
import modifycsf

extra = {}
if sys.version_info >= (3,):
    extra["use_2to3"] = True

setup(name="mcsf",
      version=modifycsf.version,
      description="Port modification wrapper for ConfigServer Security&Firewall",
      url="http://github.com/Liamraystanley/modify-csf",
      author="Liam Stanley",
      author_email="me@liamstanley.io",
      license="MIT",
      packages=["modifycsf"],
      scripts=['mcsf'],
      **extra)
