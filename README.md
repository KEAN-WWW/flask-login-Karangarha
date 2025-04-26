[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/sAJorhV0)

# Flask-Form-Login

In this assignment, you need to finish the login module. Meanwhile, the registration module here is made out of order so not need to modify it.

This is a project 2, so it may require some efforts to finish and meant to be a bit hard.




## Setup

```bash
git install -r requirements.txt
```
    
## Requirement

- Finish login form

- Finish login module, where:
  - if no valid user, pop 'User Not Found' 
  - if password Incorrect, pop 'Password Incorrect'
  - if user is valid, login the user and redirect to dashboard. Meanwhile, display its id on page.

       



## Some Tips
You will need to use a new module called flask_login to help you manage the session. The following code is what you need to complish the functionality:

```python
from flask_login import login_user, login_required, current_user, logout_user
```

**login_user**, **logout_user** are supposed to put in corresponding login and logout function.

**login_required** works as a decorator. 

**current_user** is used to set its '**is_authenticated**' property to display the correct information on HTML: 
- without login, you should only see register(out of order) and login
- with login, you should see dashboard and logout


[In case you have no idea how to start, here is an example you can refer to above code usage](https://www.geeksforgeeks.org/how-to-add-authentication-to-your-app-with-flask-login/)



## Running Tests

To run tests, run the following command

```bash
  pytest --pylint
```


