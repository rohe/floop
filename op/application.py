import os
from urllib.parse import urlparse

from flask.app import Flask

from oidcendpoint.endpoint_context import EndpointContext
from oidcmsg.key_jar import init_key_jar
from oidcop.cookie import CookieDealer

folder = os.path.dirname(os.path.realpath(__file__))
#folder = os.path.abspath(os.curdir)


def init_oidc_op_endpoints(app):
    _config = app.config.get('CONFIG')
    _server_info_config = _config['server_info']

    for path,val in app.config.get('PATH').items():
        pos = _server_info_config
        part = path.split(':')
        for p in part[:-1]:
            try:
                pos = pos[p]
            except TypeError:
                p = int(p)
                pos = pos[p]
        pos[part[-1]] = val.format(folder)

    _jwks_def = _server_info_config['jwks']
    _jwks_def['public_path'] = _jwks_def['public_path'].format(folder)
    _jwks_def['private_path'] = _jwks_def['private_path'].format(folder)
    _kj = init_key_jar(iss=_server_info_config['issuer'], **_jwks_def)

    # _jwks = _kj.export_jwks_as_json(True, '')
    # _kj.import_jwks_as_json(_jwks, )

    cookie_dealer = CookieDealer(**_server_info_config['cookie_dealer'])

    endpoint_context = EndpointContext(_server_info_config, keyjar=_kj,
                                       cwd=folder, cookie_dealer=cookie_dealer)
    cookie_dealer.endpoint_context = endpoint_context

    for endp in endpoint_context.endpoint.values():
        p = urlparse(endp.endpoint_path)
        _vpath = p.path.split('/')
        if _vpath[0] == '':
            endp.vpath = _vpath[1:]
        else:
            endp.vpath = _vpath

    return endpoint_context


def oidc_provider_init_app(name=None, **kwargs):
    name = name or __name__
    app = Flask(name, static_url_path='', **kwargs)
    app.config.from_pyfile(os.path.join(folder,'conf.py'))

    #app.users = {'test_user': {'name': 'Testing Name'}}

    try:
        from .views import oidc_op_views
    except ImportError:
        from views import oidc_op_views

    app.register_blueprint(oidc_op_views)

    # Initialize the oidc_provider after views to be able to set correct urls
    app.endpoint_context = init_oidc_op_endpoints(app)

    return app