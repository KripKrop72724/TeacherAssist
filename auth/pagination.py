from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response

class CustomPageNumberPagination(PageNumberPagination):
    page_query_param      = "page"
    page_size_query_param = "size"
    max_page_size         = 500

    def paginate_queryset(self, queryset, request, view=None):
        # for ?all=1 or ?all=true/yes
        all_flag = request.query_params.get("all", "").lower()
        if all_flag in ("1", "true", "yes"):
            return None

        return super().paginate_queryset(queryset, request, view)

    def get_paginated_response(self, data):
        return Response({
            "count":    self.page.paginator.count,
            "next":     self.get_next_link(),
            "previous": self.get_previous_link(),
            "page":     self.page.number,
            "pages":    self.page.paginator.num_pages,
            "size":     self.page.paginator.per_page,
            "results":  data,
        })
