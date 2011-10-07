from setuptools import setup, find_packages
setup(
    name = "pglb",
    version = "1.0-beta1",
    description='PowerDNS pipe backend providing dynamic resolution based on http monitors.',
    author='Mohamed Lrhazi',
    author_email='ml623@georgetown.edu',
    packages = find_packages(),
    scripts = ['pdns-glb.py'],

    # Project uses suds SOAP client module.
    install_requires = [
        'gevent>=0.13.6',
        ],

)

