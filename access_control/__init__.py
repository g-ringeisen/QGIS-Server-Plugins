# -*- coding: utf-8 -*-

def serverClassFactory(serverIface):
    from .access_control import AccessControl
    return AccessControl(serverIface)
