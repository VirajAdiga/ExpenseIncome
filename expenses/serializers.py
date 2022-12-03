from rest_framework import serializers

from expenses.models import Expense


class ExpenseSerializer(serializers.ModelSerializer):
    category = serializers.CharField()
    amount = serializers.DecimalField(max_digits=50, decimal_places=2)

    class Meta:
        model = Expense
        fields = ['category', 'amount']

    def create(self, validated_data, **kwargs):
        instance = Expense.objects.create(**validated_data, **kwargs)
        return instance
