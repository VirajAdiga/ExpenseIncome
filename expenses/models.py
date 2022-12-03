from django.db import models

from expenses.constants import EXPENSE_CATEGORY
from users.models import User


class Expense(models.Model):
    category = models.CharField(choices=EXPENSE_CATEGORY, max_length=10)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(decimal_places=2, max_digits=50)
