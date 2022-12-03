from django.core.cache import cache

from rest_framework import permissions
from rest_framework.generics import ListAPIView, CreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework.response import Response

from expenses.models import Expense
from expenses.permissions import ExpenseObjPermission
from expenses.serializers import ExpenseSerializer


class ListExpensesView(ListAPIView):
    queryset = Expense.objects.all()
    serializer_class = ExpenseSerializer
    permission_classes = permissions.IsAuthenticated,

    def get_queryset(self):
        qs = cache.get(f'expense:{self.request.user.username}:all', '')
        if qs:
            print("Cache hit")
            return qs
        print("Cache miss")
        qs = self.queryset.filter(owner=self.request.user)
        cache.set(f'expense:{self.request.user.username}:all', qs)
        return qs


class AddExpenseView(CreateAPIView):
    serializer_class = ExpenseSerializer
    permission_classes = permissions.IsAuthenticated,

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.create(serializer.validated_data, owner=self.request.user)
        cache.delete(f'expense:{self.request.user.username}:all')
        print("Cache key deleted")
        return Response({
            'data': self.serializer_class(instance).data
        })


class ExpenseRUDView(RetrieveUpdateDestroyAPIView):
    serializer_class = ExpenseSerializer
    lookup_field = 'id'
    permission_classes = permissions.IsAuthenticated, ExpenseObjPermission
    queryset = Expense.objects.all()
