from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    ROLE_CHOICES = [
        ('Coordinator', 'Coordinator'),
        ('Slot Coordinator', 'Slot Coordinator'),
        ('Admin', 'Admin'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(blank=True, null=True)
    entry_number = models.CharField(max_length=20, unique=True, blank=True, null=True)
    mobile_number = models.CharField(max_length=15, blank=True, null=True)
    webmail = models.EmailField(blank=True, null=True)
    profile_pic = models.ImageField(upload_to='profile_pics', blank=True, null=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='Slot Coordinator')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.username}'s profile"

class ApprovalRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='approval_request')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    requested_role = models.CharField(max_length=20, default='Slot Coordinator')
    message = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    reviewed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviewed_requests')
    review_comments = models.TextField(blank=True, null=True)
    
    def __str__(self):
        return f"{self.user.username}'s approval request - {self.status}"

class Announcement(models.Model):
    title = models.CharField(max_length=200)
    content = models.TextField()
    date_posted = models.DateTimeField(auto_now_add=True)
    image = models.ImageField(upload_to='announcement_images', blank=True, null=True)
    venue = models.CharField(max_length=200, blank=True, null=True)
    time = models.DateTimeField(blank=True, null=True)
    
    def __str__(self):
        return self.title

class Download(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='downloads')
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=100)
    uploaded_date = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.title

class Brochure(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='brochures/')
    year = models.IntegerField(default=2024)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} ({self.year})"

    class Meta:
        ordering = ['-year', '-created_at']

class Report(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='reports/')
    year = models.IntegerField(default=2024)
    location = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.location} ({self.year})"

    class Meta:
        ordering = ['-year', '-created_at']

class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.name} - {self.subject}"

    class Meta:
        ordering = ['-created_at']


# Screening test paper   
class PYP(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='pyp/')
    exam_date = models.DateField()
    location = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.location} ({self.exam_date})"

    class Meta:
        ordering = ['exam_date', '-created_at']
        verbose_name = "Screening Test Paper"
        
# Surprise test paper
class STP(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='stp/')
    exam_date = models.DateField()
    location = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.location} ({self.exam_date})"

    class Meta:
        ordering = ['exam_date', '-created_at']
        verbose_name = "Surprise Test Paper"
        
#weekly test paper
class WTP(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='wtp/')
    exam_date = models.DateField()
    location = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.location} ({self.exam_date})"

    class Meta:
        ordering = ['exam_date', '-created_at']
        verbose_name = "Weekly Test Paper"
        
# Screening test result
class PYR(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='wtp/')
    result_date = models.DateField()
    location = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.location} ({self.result_date})"

    class Meta:
        ordering = ['result_date', '-created_at']
        verbose_name = "Screening Test Result"
        
#Surprise test result
class STR(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='wtp/')
    result_date = models.DateField()
    location = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.location} ({self.result_date})"

    class Meta:
        ordering = ['result_date', '-created_at']
        verbose_name = "Surprise Test Result"
    
#Weekly test result
class WTR(models.Model):
    title = models.CharField(max_length=200)
    file = models.FileField(upload_to='wtp/')
    result_date = models.DateField()
    location = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} - {self.location} ({self.result_date})"

    class Meta:
        ordering = ['result_date', '-created_at']
        verbose_name = "Weekly Test Result"
        
#updates for a camp admin frontend        
class Update(models.Model):
    camp = models.ForeignKey('Camp', on_delete=models.CASCADE, related_name='updates')
    title = models.CharField(max_length=200)
    text = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='updates')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    venue = models.CharField(max_length=200, blank=True, null=True)
    time = models.DateTimeField(blank=True, null=True)


    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Update by {self.author.username} for {self.camp.name}"
 
class Camp(models.Model):
    title = models.CharField(max_length=200)
    year = models.IntegerField()
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    location = models.CharField(max_length=200, editable=False)
    image = models.ImageField(upload_to='camp_images/', blank=True, null=True)
    # This is the single source of truth for student count
    total_students = models.IntegerField(default=0,editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        # Automatically generate the location string from city and state
        self.location = f"{self.city}, {self.state}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.title} - {self.location} ({self.year})"
    
    class Meta:
        indexes = [
            models.Index(fields=['city']),
            models.Index(fields=['state']),
            models.Index(fields=['year']),
        ]
        ordering = ['-year', 'state', 'city']

class Gallery(models.Model):
    TYPE_CHOICES = [
        ('regularclasses', 'Regular Classes'),
        ('doubts', 'Doubts'),
        ('exams', 'Exams'),
    ]
    
    title = models.CharField(max_length=200)
    camp = models.ForeignKey(Camp, on_delete=models.CASCADE, related_name='gallery_images')
    # Keep location for backward compatibility, but make it computed from camp
    location = models.CharField(max_length=100, db_index=True, editable=False)
    image = models.ImageField(upload_to='gallery/')
    description = models.TextField(blank=True, null=True)
    date = models.DateField()
    type = models.CharField(max_length=20, choices=TYPE_CHOICES, default='regularclasses')
    year = models.IntegerField(editable=False)  # Will be set from camp's year
    # Make student_count read-only - it will be updated by signals
    student_count = models.PositiveIntegerField(default=0, editable=False)
    
    def save(self, *args, **kwargs):
        # Set location and year from the camp
        if self.camp:
            self.location = self.camp.location
            self.year = self.camp.year
            # Set student_count from camp's total_students
            self.student_count = self.camp.total_students
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.title} - {self.location} ({self.year})"
    
    class Meta:
        indexes = [
            models.Index(fields=['location']),
            models.Index(fields=['type']),
            models.Index(fields=['year']),
            models.Index(fields=['date']),
        ]
        ordering = ['-date']

class Student(models.Model):
    STANDARD_CHOICES = [
        ('Nursery', 'Nursery'),
        ('LKG', 'LKG'),
        ('UKG', 'UKG'),
    ] + [(str(i), str(i)) for i in range(1, 11)] + [
        ('11 (M)', '11 (M)'),
        ('11 (B)', '11 (B)'),
        ('12 (M)', '12 (M)'),
        ('12 (B)', '12 (B)'),
        ('Dropper', 'Dropper'),
    ]
    
    name = models.CharField(max_length=200, db_index=True)
    # Link student directly to camp instead of location
    camp = models.ForeignKey(Camp, on_delete=models.CASCADE, related_name='students')
    standard = models.CharField(max_length=10, choices=STANDARD_CHOICES, db_index=True)
    registration_date = models.DateField(auto_now_add=True)
    avatar = models.ImageField(upload_to='student_avatars/', blank=True, null=True)
    
    # Additional student information
    email = models.EmailField(blank=True, null=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['registration_date']),
        ]
        ordering = ['standard', 'name']
    
    def __str__(self):
        return f"{self.name} - {self.standard} ({self.camp.title})"