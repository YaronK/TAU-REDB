from django.conf.urls import patterns, include, url
import redb_app.urls

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'REDBServer.views.home', name='home'),
    # url(r'^REDBServer/', include('REDBServer.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),

    # user auth urls
    url(r'^accounts/login/$', "REDBServer.views.login_view"),
    url(r'^accounts/auth/$', "REDBServer.views.auth_view"),
    url(r'^accounts/logout/$', "REDBServer.views.logout_view"),
    # Uncomment to disallow user-registration
    url(r'^accounts/register/$', "REDBServer.views.register_view"),
    url(r'^redb/$', include(redb_app.urls)),
)
