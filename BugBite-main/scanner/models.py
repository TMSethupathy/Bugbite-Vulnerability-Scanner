from django.db import models

# Create your models here.
class Scan(models.Model):
    projectname=models.CharField(max_length=200)
    url=models.CharField(max_length=200)
    description=models.CharField(max_length=200)

    def __str__(self):
        return self.projectname
class TargetDetails(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    domain_name = models.CharField(max_length=200)
    ip = models.CharField(max_length=200)
    report_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.domain_name


class ServiceDetails(models.Model):
    target = models.ForeignKey(TargetDetails, on_delete=models.CASCADE)
    name = models.CharField(max_length=50)
    port = models.IntegerField()
    product = models.CharField(max_length=50)
    version = models.CharField(max_length=50)
    script_name = models.CharField(max_length=50)
    script_data = models.CharField(max_length=255)

    def __str__(self):
        return f'{self.name} on port {self.port}'


class OSInformation(models.Model):
    target = models.ForeignKey(TargetDetails, on_delete=models.CASCADE)
    os_name = models.CharField(max_length=50)
    accuracy = models.PositiveIntegerField()
    os_family = models.CharField(max_length=50)
    os_type = models.CharField(max_length=50)
    vendor = models.CharField(max_length=50)

    def __str__(self):
        return f'{self.os_name} ({self.accuracy}%)'

class ScanResult(models.Model):
    target = models.ForeignKey(TargetDetails, on_delete=models.CASCADE)
    scan_type = models.CharField(max_length=255)
    scan_result = models.TextField()

    
    def __str__(self):
        return self.scan_result