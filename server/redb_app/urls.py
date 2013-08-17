from django.conf.urls import patterns, url

urlpatterns = patterns('',
    url(r'^test/$', 'redb_app.views.test_handler'),
    url(r'^$', 'redb_app.views.general_handler'),
)
