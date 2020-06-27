import setuptools

# reading long description from file 
with open('DESCRIPTION.txt') as file: 
	long_description = file.read() 


# specify requirements of your package here 
REQUIREMENTS = ['requests','json'] 

# some more details 
CLASSIFIERS = [ 
	'Development Status :: 1 - Planning', 
	'Intended Audience :: Developers', 
	'Topic :: Software Development :: Libraries', 
	'License :: OSI Approved :: MIT License', 
    'Framework :: Flask',
    'Programming Language :: Python', 
	'Programming Language :: Python :: 2', 
	'Programming Language :: Python :: 2.6', 
	'Programming Language :: Python :: 2.7', 
	'Programming Language :: Python :: 3', 
	'Programming Language :: Python :: 3.3', 
	'Programming Language :: Python :: 3.4', 
	'Programming Language :: Python :: 3.5', 
    'Programming Language :: Python :: Implementation :: PyPy',
    'Typing :: Typed'
	] 

# calling the setup function 
setuptools.setup(name='A5Orchestrator', 
	version='1.0.0', 
	description='This module helps to intigrate Orchestrator with python scripts ', 
	long_description='This module helps to intigrate Orchestrator with python scripts ', 
	url='https://github.com/akvdkharnath/A5Orchestrator.git', 
	author='Harnath Atmakuri', 
	author_email='akvdkharnath@gmail.com', 
	license='MIT', 
	packages=setuptools.find_packages(), 
	classifiers=CLASSIFIERS, 
	install_requires=REQUIREMENTS
	) 
