# Voodoo Search
Voodoo search is a project to make searching whatever you want and try to come back with some sort of data. Currently, I'm only looking at IPs, emails, and domains, but the ability to expand is here. It's all designed to run as a lambda with a API gateway in front of it (see the lmabda_function.py). It can be ran locally (see voodoo.example). There's even a bitbucket yaml to make this a full CI/CD deployment to lambda
## voodoo unittest
```
python voodoo_unittest.py -b
```
