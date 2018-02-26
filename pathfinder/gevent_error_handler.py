# -*- coding: utf-8 -*-
from gevent.hub import Hub

IGNORE_ERROR = Hub.SYSTEM_ERROR + Hub.NOT_ERROR


def register_error_handler(error_handler):

    Hub._origin_handle_error = Hub.handle_error

    def custom_handle_error(self, context, type, value, tb):
        if not issubclass(type, IGNORE_ERROR):
            # print 'Got error from greenlet:', context, type, value, tb
            error_handler(context, (type, value, tb))

        self._origin_handle_error(context, type, value, tb)

    Hub.handle_error = custom_handle_error
