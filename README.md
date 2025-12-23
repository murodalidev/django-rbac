# Django REST Framework: RBAC (Role-Based Access Control) 

> **Description:** Django REST Framework loyihalarida admin dashboard va klientlar uchun API yaratishda ikkita yondashuv bor: ikki alohida API endpoint yoki bitta API rollar orqali boshqarish. Bu maqolada biz nima uchun ikkinchi usulni tanlaganimizni va RBAC (Role-Based Access Control) tizimini qanday amalga oshirishni batafsil tushuntiramiz. Kod misollari, amaliy misollar va best practices bilan.

---

## Kirish

Django REST Framework loyihalarida admin dashboard va klientlar uchun API yaratishda eng muhim qarorlardan biri - bu API arxitekturasini qanday tuzish. Bu maqolada biz ikkita yondashuvni tahlil qilamiz va nima uchun **bitta API rollar orqali boshqarish** usulini tanlaganimizni batafsil tushuntiramiz.

## Muammo: Admin va Klientlar uchun API

Har qanday e-commerce yoki kontent boshqarish tizimida ikki xil foydalanuvchi turi mavjud:

1. **Admin/Manager** - Barcha ma'lumotlarni ko'radi va boshqaradi
2. **Klientlar/Umumiy foydalanuvchilar** - Faqat faol (active) ma'lumotlarni ko'radi

Masalan, yangiliklar (News) moduli uchun:
- Admin: Barcha yangiliklarni ko'radi (faol va nofaol)
- Klientlar: Faqat faol yangiliklarni ko'radi

## Ikki Yondashuv

### 1-usul: Ikki Alohida API Endpoint

```
/api/v1/admin/news/     - Admin uchun
/api/v1/web/news/       - Klientlar uchun
```

**Qanday ishlaydi:**
- Har bir endpoint uchun alohida ViewSet
- Har bir endpoint uchun alohida Serializer
- Har bir endpoint uchun alohida URL route

**Muammolar:**
- ❌ Kod takrorlanishi (DRY prinsipi buziladi)
- ❌ Maintenance qiyin (ikkita joyda o'zgartirish kerak)
- ❌ Test qilish qiyin (ikkita endpoint test qilish kerak)
- ❌ Mavjud permission tizimidan foydalanilmaydi
- ❌ Scalability muammosi (har yangi role uchun yangi endpoint)

**Kod misoli:**
```python
# apps/main/views.py
class AdminNewsViewSet(viewsets.ModelViewSet):
    queryset = News.objects.all()  # Barcha yangiliklar
    serializer_class = AdminNewsSerializer  # is_active ko'rinadi

class WebNewsViewSet(viewsets.ModelViewSet):
    queryset = News.objects.filter(is_active=True)  # Faqat faol
    serializer_class = WebNewsSerializer  # is_active ko'rinmaydi
```

### 2-usul: Bitta API Rollar Orqali (Bizning Tanlovimiz ✅)

```
/api/v1/news/           - Bitta endpoint, rollar orqali boshqariladi
```

**Qanday ishlaydi:**
- Bitta ViewSet, lekin role-based filtering
- Serializerlar orqali response formatlari ajratiladi
- Permission tizimi orqali access control

**Afzalliklari:**
- ✅ Kod takrorlanmaydi (DRY prinsipi)
- ✅ Maintenance oson (bitta joyda o'zgartirish)
- ✅ Mavjud permission tizimidan to'liq foydalanish
- ✅ Flexible va scalable
- ✅ Test qilish oson

**Kod misoli:**
```python
# apps/main/views.py
class NewsViewSet(viewsets.ModelViewSet):
    permission_resource = "news"
    permission_classes = [IsAuthenticatedOrReadOnly, HasDynamicPermission]
    
    def get_queryset(self):
        queryset = News.objects.filter(is_deleted=False)
        
        # Admin/Manager: barcha yangiliklar
        if self.request.user.has_role('admin') or self.request.user.has_role('manager'):
            return queryset
        
        # Klientlar: faqat faol yangiliklar
        return queryset.filter(is_active=True)
    
    def get_serializer_class(self):
        # Admin uchun: barcha fieldlar
        if self.action in ["create", "update", "partial_update"]:
            return NewsCreateUpdateSerializer
        
        # Klientlar uchun: is_active/is_deleted ko'rinmaydi
        return NewsSerializer
```

## Nima Uchun 2-usulni Tanladik?

### 1. Mavjud Infrastruktura

Loyihamizda allaqachon quyidagi tizimlar mavjud:

- **Dynamic Permission System** - Database-dan permissionlarni o'qiydi
- **Role-Based Access Control** - Admin, Manager, Client rollari
- **Permission Classes** - `HasDynamicPermission` allaqachon tayyor

### 2. DRY Prinsipi (Don't Repeat Yourself)

Bitta kod, ko'p funksionallik. Bu o'zgarishlarni bitta joyda qilish imkonini beradi.

### 3. Scalability

Yangi role qo'shganda yangi endpoint yaratish shart emas. Faqat permission qo'shish kifoya.

### 4. Maintenance

Bitta joyda o'zgartirish - barcha foydalanuvchilar uchun ishlaydi.

## RBAC (Role-Based Access Control) - To'liq Tushuntirish

### RBAC Nima?

RBAC - bu foydalanuvchilarga rollar berish va har bir role uchun alohida permissionlar belgilash tizimi.

**Asosiy tushunchalar:**
- **Role** - Foydalanuvchi roli (Admin, Manager, Client)
- **Permission** - Ruxsat (view, add, change, delete)
- **Resource** - Resurs (news, products, orders)

**Misol:**
- Admin → news → view, add, change, delete (barcha ruxsatlar)
- Client → news → view (faqat ko'rish)

## Django-da RBAC Amalga Oshirish

### 1-qadam: Modellar Yaratish

#### Role Modeli

```python
# apps/accounts/models.py
class Role(models.Model):
    """
    Role modeli - Admin, Manager, Client kabi rollar
    """
    name = models.CharField(_('name'), max_length=100, unique=True)
    description = models.TextField(_('description'), blank=True)
    is_active = models.BooleanField(_('active'), default=True)
    created_at = models.DateTimeField(_('created at'), auto_now_add=True)
    
    class Meta:
        verbose_name = _('Role')
        verbose_name_plural = _('Roles')
        ordering = ['name']
    
    def __str__(self):
        return self.name
```

#### Permission Modeli

```python
class Permission(models.Model):
    """
    Permission modeli - view, add, change, delete kabi ruxsatlar
    """
    resource = models.CharField(_('resource'), max_length=100)  # 'news', 'products'
    action = models.CharField(_('action'), max_length=50)  # 'view', 'add', 'change', 'delete'
    name = models.CharField(_('name'), max_length=200)
    description = models.TextField(_('description'), blank=True)
    is_active = models.BooleanField(_('active'), default=True)
    
    class Meta:
        verbose_name = _('Permission')
        verbose_name_plural = _('Permissions')
        unique_together = [['resource', 'action']]
        ordering = ['resource', 'action']
    
    def __str__(self):
        return f"{self.resource}.{self.action}"
```

#### RolePermission Modeli (Many-to-Many)

```python
class RolePermission(models.Model):
    """
    Role va Permission o'rtasidagi bog'lanish
    """
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_permissions')
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE, related_name='role_permissions')
    conditions = models.JSONField(_('conditions'), blank=True, null=True)  # Object-level permissions uchun
    
    class Meta:
        verbose_name = _('Role Permission')
        verbose_name_plural = _('Role Permissions')
        unique_together = [['role', 'permission']]
    
    def __str__(self):
        return f"{self.role.name} - {self.permission.name}"
```

#### UserRole Modeli

```python
class UserRole(models.Model):
    """
    User va Role o'rtasidagi bog'lanish
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='user_roles')
    assigned_at = models.DateTimeField(_('assigned at'), auto_now_add=True)
    expires_at = models.DateTimeField(_('expires at'), blank=True, null=True)
    is_active = models.BooleanField(_('active'), default=True)
    
    class Meta:
        verbose_name = _('User Role')
        verbose_name_plural = _('User Roles')
        unique_together = [['user', 'role']]
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.role.name}"
```

### 2-qadam: User Modeliga Metodlar Qo'shish

```python
# apps/accounts/models.py
class User(AbstractUser):
    # ... boshqa fieldlar ...
    
    def has_role(self, role_name: str) -> bool:
        """
        Foydalanuvchining ma'lum roli bor-yo'qligini tekshirish
        
        Args:
            role_name: Role nomi ('admin', 'manager', 'client')
            
        Returns:
            bool: True agar role bor bo'lsa
        """
        return self._get_active_user_roles_qs().filter(
            role__name=role_name
        ).exists()
    
    def has_permission(self, resource: str, action: str, obj=None) -> bool:
        """
        Foydalanuvchining ma'lum permission bor-yo'qligini tekshirish
        
        Args:
            resource: Resurs nomi ('news', 'products')
            action: Amal nomi ('view', 'add', 'change', 'delete')
            obj: Object-level permission uchun (ixtiyoriy)
            
        Returns:
            bool: True agar permission bor bo'lsa
        """
        # Admin barcha ruxsatlarga ega
        if self.has_role('admin'):
            return True
        
        # Foydalanuvchining aktiv rollarini olish
        active_roles = self._get_active_user_roles_qs()
        
        # Har bir role uchun permissionlarni tekshirish
        for user_role in active_roles:
            role_permissions = user_role.role.role_permissions.filter(
                permission__resource=resource,
                permission__action=action,
                permission__is_active=True
            )
            
            for role_permission in role_permissions:
                # Object-level permission tekshirish
                if obj and role_permission.conditions:
                    if self._check_conditions(role_permission.conditions, obj):
                        return True
                elif not obj:
                    return True
        
        return False
    
    def _get_active_user_roles_qs(self):
        """Aktiv (muddati o'tmagan) rollarni qaytaradi"""
        from django.utils import timezone
        current = timezone.now()
        return (
            self.user_roles.filter(
                role__is_active=True,
                expires_at__isnull=True,
                is_active=True
            ) | self.user_roles.filter(
                role__is_active=True,
                expires_at__gt=current,
                is_active=True
            )
        ).select_related('role')
```

### 3-qadam: Permission Class Yaratish

```python
# core/permissions.py
from rest_framework.permissions import BasePermission
from rest_framework.request import Request
from rest_framework.views import APIView

class HasDynamicPermission(BasePermission):
    """
    Dynamic permission class - database-dan permissionlarni o'qiydi
    """
    
    def has_permission(self, request: Request, view: APIView) -> bool:
        """
        Foydalanuvchining permission bor-yo'qligini tekshirish
        
        Args:
            request: HTTP request
            view: ViewSet yoki APIView
            
        Returns:
            bool: True agar permission bor bo'lsa
        """
        # AnonymousUser ruxsat olmaydi
        if not request.user or isinstance(request.user, AnonymousUser):
            return False
        
        # View dan permission_resource va permission_action olish
        resource = getattr(view, 'permission_resource', None)
        action = getattr(view, 'permission_action', None)
        
        # Resource majburiy
        if not resource:
            return False
        
        # Action avtomatik aniqlash (GET → view, POST → add, ...)
        if not action:
            action = self._get_action_from_method(request.method)
        
        # Permission tekshirish
        return request.user.has_permission(resource, action)
    
    def _get_action_from_method(self, method: str) -> str:
        """HTTP method dan action aniqlash"""
        method_mapping = {
            'GET': 'view',
            'POST': 'add',
            'PUT': 'change',
            'PATCH': 'change',
            'DELETE': 'delete',
        }
        return method_mapping.get(method.upper(), 'view')
```

### 4-qadam: ViewSet-larni Sozlash

```python
# apps/main/views.py
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from core.permissions import HasDynamicPermission

class NewsViewSet(viewsets.ModelViewSet):
    """
    News ViewSet - barcha foydalanuvchilar uchun
    """
    queryset = News.objects.filter(is_deleted=False)
    serializer_class = NewsSerializer
    
    # Permission sozlash
    permission_classes = [IsAuthenticatedOrReadOnly, HasDynamicPermission]
    permission_resource = "news"  # Bu resource uchun permission tekshiriladi
    
    # Filter, search, ordering
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["title", "slug", "description"]
    ordering = ["-created_at"]
    
    def get_queryset(self):
        """
        Role-based filtering
        """
        queryset = super().get_queryset()
        
        # Admin va Manager: barcha yangiliklar
        is_admin_or_manager = (
            self.request.user.is_authenticated
            and hasattr(self.request.user, 'has_role')
            and (
                self.request.user.has_role('admin')
                or self.request.user.has_role('manager')
            )
        )
        
        if not is_admin_or_manager:
            # Klientlar: faqat faol yangiliklar
            queryset = queryset.filter(is_active=True)
        
        # Performance optimizatsiyasi
        queryset = queryset.select_related('category').prefetch_related('images')
        
        return queryset
    
    def get_serializer_class(self):
        """
        Action ga qarab serializer tanlash
        """
        # Admin uchun: barcha fieldlar (is_active ko'rinadi)
        if self.action in ["create", "update", "partial_update"]:
            return NewsCreateUpdateSerializer
        
        # Klientlar uchun: is_active/is_deleted ko'rinmaydi
        elif self.action == "retrieve":
            return NewsDetailSerializer
        
        # List uchun
        return NewsSerializer
```

### 5-qadam: Serializer-larni Sozlash

```python
# apps/main/serializers.py
from rest_framework import serializers

class NewsSerializer(serializers.ModelSerializer):
    """
    Web API uchun - is_active va is_deleted ko'rinmaydi
    """
    category = NewsCategorySerializer(read_only=True)
    images = serializers.SerializerMethodField()
    
    class Meta:
        model = News
        fields = [
            "id",
            "category",
            "title",
            "slug",
            "description",
            "images",
            "created_at",
            "updated_at",
            # is_active va is_deleted yo'q!
        ]
        read_only_fields = ["id", "slug", "created_at", "updated_at"]
    
    def get_images(self, obj):
        """Faqat o'chirilmagan rasmlarni qaytarish"""
        images = obj.images.filter(is_deleted=False)
        return NewsImageSerializer(images, many=True).data


class NewsCreateUpdateSerializer(serializers.ModelSerializer):
    """
    Admin API uchun - barcha fieldlar ko'rinadi
    """
    class Meta:
        model = News
        fields = [
            "id",
            "category",
            "title",
            "slug",
            "description",
            "is_active",  # Admin ko'radi
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "slug", "created_at", "updated_at"]
```

## Amaliy Misol: News Moduli

### 1. Database-da Permission Yaratish

```python
# Management command yoki admin panel orqali

# Permission yaratish
Permission.objects.create(
    resource='news',
    action='view',
    name='View News',
    description='View news articles'
)

Permission.objects.create(
    resource='news',
    action='add',
    name='Add News',
    description='Create new news articles'
)

Permission.objects.create(
    resource='news',
    action='change',
    name='Change News',
    description='Edit news articles'
)

Permission.objects.create(
    resource='news',
    action='delete',
    name='Delete News',
    description='Delete news articles'
)
```

### 2. Role-ga Permission Berish

```python
# Admin role ga barcha permissionlar
admin_role = Role.objects.get(name='admin')
news_permissions = Permission.objects.filter(resource='news')

for permission in news_permissions:
    RolePermission.objects.get_or_create(
        role=admin_role,
        permission=permission
    )

# Client role ga faqat view permission
client_role = Role.objects.get(name='client')
view_permission = Permission.objects.get(resource='news', action='view')

RolePermission.objects.get_or_create(
    role=client_role,
    permission=view_permission
)
```

### 3. User-ga Role Berish

```python
# User ga role berish
user = User.objects.get(phone='+998901234567')
admin_role = Role.objects.get(name='admin')

UserRole.objects.get_or_create(
    user=user,
    role=admin_role
)
```

## Natija

### Admin Request

```bash
GET /api/v1/news/
Authorization: Bearer <admin_token>
```

**Response:**
```json
{
    "count": 10,
    "results": [
        {
            "id": 1,
            "title": "Yangi yangilik",
            "slug": "yangi-yangilik",
            "description": "...",
            "is_active": true,  // Admin ko'radi
            "created_at": "2024-01-01T00:00:00Z"
        }
    ]
}
```

### Client Request

```bash
GET /api/v1/news/
Authorization: Bearer <client_token>
```

**Response:**
```json
{
    "count": 5,  // Faqat faol yangiliklar
    "results": [
        {
            "id": 1,
            "title": "Yangi yangilik",
            "slug": "yangi-yangilik",
            "description": "...",
            // is_active yo'q - klient ko'rmaydi
            "created_at": "2024-01-01T00:00:00Z"
        }
    ]
}
```

## Xulosa

**Bitta API rollar orqali boshqarish** usuli:

✅ **Kod takrorlanmaydi** - DRY prinsipi  
✅ **Maintenance oson** - bitta joyda o'zgartirish  
✅ **Scalable** - yangi rollar qo'shish oson  
✅ **Flexible** - har xil permission kombinatsiyalari  
✅ **Secure** - database-dan permissionlar o'qiladi  

Bu usul professional Django loyihalarida eng ko'p ishlatiladigan yondashuvdir va bizning loyihamizda ham muvaffaqiyatli ishlayapti.

## Tez-tez So'raladigan Savollar (FAQ)

### 1. Agar yangi role qo'shmoqchi bo'lsam?

```python
# 1. Role yaratish
new_role = Role.objects.create(
    name='moderator',
    display_name='Moderator',
    description='Content moderator'
)

# 2. Permission berish
moderator_permissions = Permission.objects.filter(
    resource='news',
    action__in=['view', 'change']  # Faqat ko'rish va o'zgartirish
)

for permission in moderator_permissions:
    RolePermission.objects.create(
        role=new_role,
        permission=permission
    )
```

### 2. Object-level permission qanday ishlaydi?

```python
# RolePermission modelida conditions field
RolePermission.objects.create(
    role=client_role,
    permission=view_permission,
    conditions={
        'is_active': True,  # Faqat faol yangiliklarni ko'rish
        'created_by': 'self'  # Faqat o'z yangiliklarini ko'rish
    }
)
```

### 3. Performance optimizatsiyasi qanday?

```python
# get_queryset da select_related va prefetch_related ishlatish
def get_queryset(self):
    queryset = News.objects.filter(is_deleted=False)
    
    # N+1 query muammosini hal qilish
    queryset = queryset.select_related('category')  # ForeignKey
    queryset = queryset.prefetch_related('images')  # ManyToMany
    
    return queryset
```

### 4. Test qanday yoziladi?

```python
# tests/test_news_views.py
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from apps.accounts.models import Role, Permission, UserRole

User = get_user_model()

class NewsAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        
        # Admin user
        self.admin = User.objects.create_user(
            phone='+998901234567',
            password='testpass123'
        )
        admin_role = Role.objects.get(name='admin')
        UserRole.objects.create(user=self.admin, role=admin_role)
        
        # Client user
        self.client_user = User.objects.create_user(
            phone='+998901234568',
            password='testpass123'
        )
        client_role = Role.objects.get(name='client')
        UserRole.objects.create(user=self.client_user, role=client_role)
    
    def test_admin_can_see_all_news(self):
        """Admin barcha yangiliklarni ko'radi"""
        self.client.force_authenticate(user=self.admin)
        response = self.client.get('/api/v1/news/')
        
        self.assertEqual(response.status_code, 200)
        # Barcha yangiliklar (faol va nofaol)
    
    def test_client_can_see_only_active_news(self):
        """Client faqat faol yangiliklarni ko'radi"""
        self.client.force_authenticate(user=self.client_user)
        response = self.client.get('/api/v1/news/')
        
        self.assertEqual(response.status_code, 200)
        # Faqat faol yangiliklar
        for news in response.data['results']:
            self.assertNotIn('is_active', news)  # is_active ko'rinmaydi
```

## Xatolarni Hal Qilish

### Muammo 1: Permission tekshirilmayapti

**Sabab:** `permission_resource` ViewSet da belgilanmagan

**Yechim:**
```python
class NewsViewSet(viewsets.ModelViewSet):
    permission_resource = "news"  # Bu qatorni qo'shing!
    permission_classes = [HasDynamicPermission]
```

### Muammo 2: AnonymousUser xatosi

**Sabab:** `has_role` metodini AnonymousUser da chaqirish

**Yechim:**
```python
def get_queryset(self):
    if (
        self.request.user.is_authenticated
        and hasattr(self.request.user, 'has_role')
        and self.request.user.has_role('admin')
    ):
        # ...
```

### Muammo 3: Serializer noto'g'ri tanlanmoqda

**Sabab:** `get_serializer_class` da action tekshirilmagan

**Yechim:**
```python
def get_serializer_class(self):
    if self.action in ["create", "update", "partial_update"]:
        return NewsCreateUpdateSerializer
    elif self.action == "retrieve":
        return NewsDetailSerializer
    return NewsSerializer  # list uchun
```

## Best Practices

### 1. Permission Resource Nomlash

```python
# Yaxshi ✅
permission_resource = "news"
permission_resource = "products"
permission_resource = "orders"

# Yomon ❌
permission_resource = "news_articles"  # Noaniq
permission_resource = "n"  # Qisqa
```

### 2. Serializer Naming

```python
# Yaxshi ✅
NewsSerializer  # Web API
NewsCreateUpdateSerializer  # Admin API
NewsDetailSerializer  # Detail view

# Yomon ❌
NewsSerializer1
NewsSerializer2
```

### 3. QuerySet Filtering

```python
# Yaxshi ✅
def get_queryset(self):
    queryset = super().get_queryset()
    
    # Avval role tekshirish
    if self.request.user.has_role('admin'):
        return queryset
    
    # Keyin filter qo'llash
    return queryset.filter(is_active=True)

# Yomon ❌
def get_queryset(self):
    # Har safar filter qo'llash
    return News.objects.filter(is_active=True)
```

## Xulosa

**Bitta API rollar orqali boshqarish** usuli:

✅ **Kod takrorlanmaydi** - DRY prinsipi  
✅ **Maintenance oson** - bitta joyda o'zgartirish  
✅ **Scalable** - yangi rollar qo'shish oson  
✅ **Flexible** - har xil permission kombinatsiyalari  
✅ **Secure** - database-dan permissionlar o'qiladi  
✅ **Test qilish oson** - bitta endpoint test qilish  
✅ **Performance** - optimizatsiya qilish oson  

Bu usul professional Django loyihalarida eng ko'p ishlatiladigan yondashuvdir va bizning loyihamizda ham muvaffaqiyatli ishlayapti.

Agar sizda savollar bo'lsa yoki qo'shimcha ma'lumot kerak bo'lsa, izohlar bo'limida yozing! 🚀

## Qo'shimcha Manbalar

- Django REST Framework: https://www.django-rest-framework.org/
- RBAC Pattern: https://en.wikipedia.org/wiki/Role-based_access_control
- Django Permissions: https://docs.djangoproject.com/en/stable/topics/auth/customizing/
- DRF Permissions: https://www.django-rest-framework.org/api-guide/permissions/

---

**Muallif:** [Sizning ismingiz]  
**Sana:** 2024  
**Taglar:** Django, REST API, RBAC, Permission System, Backend Development, Python, Web Development

