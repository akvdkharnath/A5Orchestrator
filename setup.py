import setuptools

def readme():
    with open('README.md') as f:
        README = f.read()
    return README

# specify requirements of your package here 
REQUIREMENTS = ['requests','json'] 

# some more details 
CLASSIFIERS = [ 
	'Development Status :: 1 - Planning', 
	'Intended Audience :: Developers', 
	'Topic :: Software Development :: Libraries', 
	'License :: OSI Approved :: MIT License', 
    'Programming Language :: Python :: 2.7', 
	'Programming Language :: Python :: 3', 
    ] 

# calling the setup function 
setuptools.setup(name='A5Orchestrator', 
	version='1.0.5', 
	description='This module helps to intigrate Orchestrator with python scripts ', 
	long_description='This module helps to intigrate Orchestrator with python scripts ', 
	long_description_content_type="text/markdown",
	url='https://github.com/akvdkharnath/A5Orchestrator.git', 
	author='Harnath Atmakuri', 
	author_email='akvdkharnath@gmail.com', 
	license='MIT', 
	packages=['A5Orchestrator'], 
	include_package_data=True,
	classifiers=CLASSIFIERS, 
	install_requires=REQUIREMENTS,
	python_requires = '>=3.0',
	) 
