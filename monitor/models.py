from django.db import models

class LogFile(models.Model):
    file = models.FileField(upload_to='logs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Log File {self.id} - {self.uploaded_at}"
