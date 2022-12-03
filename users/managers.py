from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None):
        if username is None:
            raise ValueError('Username must be set')
        if email is None:
            raise ValueError("Email must be set")

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password):
        if username is None:
            raise ValueError('Username must be set')
        if email is None:
            raise ValueError("Email must be set")
        if password is None:
            raise ValueError("Password cannot be none")

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user
