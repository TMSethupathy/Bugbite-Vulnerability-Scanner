from django.contrib import admin

# Register your models here.
from .models import Scan,TargetDetails,ServiceDetails,OSInformation,ScanResult

admin.site.register(Scan)
admin.site.register(TargetDetails)
admin.site.register(ServiceDetails)
admin.site.register(OSInformation)
admin.site.register(ScanResult)