from setuptools import setup, find_packages

version = "0.0.1"
setup(
    name="zhixuewang_json",
    version=version,
    keywords=["智学网", "zhixue", "zhixuewang"],
    description="智学网的api_json版",
    license="MIT",

    author="immoses",
    author_email="i@immoses.com",

    packages=find_packages(),
    include_package_data=True,
    platforms="any",
    install_requires=["requests", "httpx", "numpy<=1.21", "rsa"],
)
