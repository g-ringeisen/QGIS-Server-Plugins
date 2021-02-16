import os
import time
import base64
import psycopg2

from qgis.core import QgsMessageLog, QgsDataSourceUri
from qgis.server import QgsAccessControlFilter, QgsServerFilter

from .config import *

class RestrictedAccessControlWithUsers(QgsAccessControlFilter):
    def __init__(self, server_iface):
        super(QgsAccessControlFilter, self).__init__(server_iface)
        self._permcache = {}
        
    def _get_user(self):
        username = None
        auth = self.serverInterface().getEnv('HTTP_AUTHORIZATION')
        if auth:
            username, password = base64.b64decode(auth[6:]).split(b':')
            username = username.decode("utf-8")
        else:
            username = self.serverInterface().getEnv(user_env_var)
        
        if username == None or username == "":
            return default_user;
        return username;
    
    def _get_postgresTablePermissions(self, layer):
        user        = self._get_user()
        uri         = QgsDataSourceUri(layer.source())
        permissions = QgsAccessControlFilter.LayerPermissions()
        cachekey    = "{} {}".format(user, uri.schema())
        
        
        rolecache = self._permcache.get(cachekey)
        if rolecache == None or time.time() - rolecache.get("_timestamp") > cache_ttl:
            
            if debug:
                QgsMessageLog.logMessage("No cache available, building new cache for {}".format(cachekey))

            # Create new cache dictionnary
            rolecache = {
                "_timestamp": time.time()
            }
            # Try to get schema permissions from Postgres
            conn = None
            curs = None
            try:
                if uri.service() != None:
                    conn = psycopg2.connect(service=uri.service())
                else:
                    conn = psycopg2.connect(dbname=uri.database(), user=uri.username(), password=uri.password(), host=uri.host(), port=uri.port())
                
                curs = conn.cursor()
                curs.execute(perms_sql, {'user': user, 'schema': uri.schema()})
                for record in curs:
                    rolecache[record[0]] = (record[1], record[2], record[3], record[4])
                self._permcache[cachekey] = rolecache
            except Exception as e:
                QgsMessageLog.logMessage("{}".format(e))
                if debug:
                    raise
            finally:
                if curs:
                    curs.close()
                if conn:
                    conn.close()
            
        perms = rolecache.get(uri.table())
        if perms:
            permissions.canRead   = perms[0]
            permissions.canInsert = perms[1]
            permissions.canUpdate = perms[2]
            permissions.canDelete = perms[3]
        else:
            permissions.canRead   = False
            permissions.canInsert = False
            permissions.canUpdate = False
            permissions.canDelete = False
        
        if debug:
            QgsMessageLog.logMessage("Permissions for {} on table {} : {}".format(user, uri.table(), perms))

        return permissions

    def layerFilterExpression(self, layer):
        """ Return an additional expression filter """
        return super(RestrictedAccessControlWithUsers, self).layerFilterExpression(layer)

    def layerFilterSubsetString(self, layer):
        """ Return an additional subset string (typically SQL) filter """
        return super(RestrictedAccessControlWithUsers, self).layerFilterSubsetString(layer)

    def layerPermissions(self, layer):
        """ Return the layer rights """
        if layer.providerType() == "postgres":
            return self._get_postgresTablePermissions(layer)
                
        return super(RestrictedAccessControlWithUsers, self).layerPermissions(layer)

    def authorizedLayerAttributes(self, layer, attributes):
        """ Return the authorised layer attributes """
        return super(RestrictedAccessControlWithUsers, self).authorizedLayerAttributes(layer, attributes)

    def allowToEdit(self, layer, feature):
        """ Are we authorise to modify the following geometry """
        return super(RestrictedAccessControlWithUsers, self).allowToEdit(layer, feature)

    def cacheKey(self):
        #return self._get_user()
        return super(RestrictedAccessControlWithUsers, self).cacheKey()


class AccessControl:
    def __init__(self, serverIface):
        # Save reference to the QGIS server interface
        serverIface.registerAccessControl( RestrictedAccessControlWithUsers(serverIface), 100 )


