import logging
import plugins

from importlib import import_module
from pkgutil import iter_modules

logger = logging.getLogger('dw')

class plugin_manager(object):

    MANDATORY_PLUGIN_FUNCTIONS = ["load_config", "call"]

    def __init__(self):

        self.plugins = {}
        logger.debug('Enumerating installed plugins')
        self.installed_plugins = self.get_installed_plugins()
        logger.debug('Found [%d] plugins' % len(self.installed_plugins))

        if len(self.installed_plugins) > 0:
            logger.debug('Loading plugins')

            for plugin_name in self.installed_plugins.keys():
                self.load(plugin_name, self.plugins)

            logger.debug("Loaded [%d] plugins" % len(self.plugins))

    def load(self, full_plugin_name, plugins):

        plugin_name = self.get_short_plugin_name(full_plugin_name)
        logger.debug('Loading plugin: %s' % plugin_name)
        if full_plugin_name:
            plugin_object = getattr(self.installed_plugins[full_plugin_name], plugin_name)

            for _func in self.MANDATORY_PLUGIN_FUNCTIONS:
                if not getattr(plugin_object, _func, None):
                    logger.error("FAILED: Plugin: %s -> Msg: Function '%s' not found!" % (full_plugin_name, _func))
                    return False

            logger.debug('Initialize the plugin object')

            plugin_object = plugin_object()

            if not plugin_object.load_config():
                logger.error('Failed to load configuration for plugin: %s' % full_plugin_name)
                return False

            plugin_type = plugin_object.plugin_type
            vendor_name = plugin_object.vendor_name

            logger.debug('Plugin: %s loaded successfully' % plugin_name)
            plugins[plugin_name] = {'full_plugin_name': full_plugin_name, "plugin_object": plugin_object,
                                  'vendor_name': vendor_name, 'plugin_type': plugin_type}
            return True
        else:
            logger.error(f"Plugin: %s is not installed!" % plugin_name)
            return False

    def get_plugins(self):

        if self.plugins:
            return self.plugins

    def get_proxy_vendors(self, vendor_names=[]):

        vendor_objects = []

        if vendor_names:
            plugins = self.get_plugin_values_by_type("PROXY")
            for plugin in plugins:
                if plugin["vendor_name"].lower() in vendor_names:
                    vendor_objects.append(plugin["plugin_object"])
            return vendor_objects
        else:
            vendor_objects = self.get_plugin_objects_by_type("PROXY")
            return vendor_objects

    def get_av_vendors(self, vendor_names=[]):

        vendor_objects = []

        if vendor_names:
            plugins = self.get_plugin_values_by_type("AV")
            for plugin in plugins:
                if plugin["vendor_name"].lower() in vendor_names:
                    vendor_objects.append(plugin["plugin_object"])
            return vendor_objects
        else:
            vendor_objects = self.get_plugin_objects_by_type("AV")
            return vendor_objects

    def get_plugin_values_by_type(self, plugin_type):

        plugin_values = []
        for plugin_name, value in self.plugins.items():
            if value["plugin_type"] == plugin_type:
                plugin_values.append(value)

        return plugin_values

    def get_plugin_objects_by_type(self, plugin_type):

        plugin_objects = []
        for plugin_name, value in self.plugins.items():
            if value["plugin_type"] == plugin_type:
                plugin_objects.append(value["plugin_object"])

        return plugin_objects

    """ Helper functions """

    def get_short_plugin_name(self, full_plugin_name):

        return full_plugin_name[full_plugin_name.rindex(".") + 1:]

    def get_installed_plugins(self):

        # Get the list of installed plugins
        installed_plugins = {
            name: import_module(name)
            for finder, name, ispkg
            in self._iter_namespace(plugins)
        }

        return installed_plugins

    def _iter_namespace(self, ns_pkg):
        # Specifying the second argument (prefix) to iter_modules makes the
        # returned name an absolute name instead of a relative one. This allows
        # import_module to work without having to do additional modification to
        # the name.
        return iter_modules(ns_pkg.__path__, ns_pkg.__name__ + ".")


class vendor():

    class type():

        AV = 0
        PROXY = 1



