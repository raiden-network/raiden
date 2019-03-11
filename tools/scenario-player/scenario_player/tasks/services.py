from scenario_player.exceptions import ScenarioAssertionError, ScenarioError
from scenario_player.tasks.api_base import RESTAPIActionTask


class PFSAssertTask(RESTAPIActionTask):
    """
    PFS Assert task

    Example usages:

        # 4 requests where made from source node 0
        assert_pfs_routes: {source: 0, request_count: 4}

        # 4 requests where made from source node 0 to target node 1
        assert_pfs_routes: {source: 0, target: 1, request_count: 4}

        # 4 requests where made from source node 0 to target node 1 and 3 routes each have been
        # returned
        assert_pfs_routes: {source: 0, target: 1, request_count: 4, routes_count: 3}

        # 4 requests where made from source node 0 to target node 1 and the specified number of
        # routes have been returned
        assert_pfs_routes: {source: 0, target: 1, request_count: 4, routes_count: [3, 2, 1, 2]}

        # The listed routes have been returned for requests from source node 0 to target node 1
        assert_pfs_routes:
          source: 0
          target: 1
          expected_routes:
            - ['0x00[...]01', '0x00[...]04']
            - ['0x00[...]01', '0x00[...]02', '0x00[...]04']

    Expected response from PFS debug endpoint:
        {
            "request_count": <int>,
            "responses": [
                {
                    "source": <address>,
                    "target": <address>,
                    "routes": [
                        [<address>, <address>, ...],
                        ...,
                    ]
                },
                ...
            ]
        }
    """
    _name = 'assert_pfs_routes'
    _url_template = "{pfs_url}/v1/_debug/routes/{token_address}/{source_address}{extra_params}"

    @property
    def _url_params(self):
        pfs_url = self._runner.scenario.settings.get('pfs', {}).get('url')
        if not pfs_url:
            raise ScenarioError('PFS tasks require settings.pfs.url to be set.')

        source = self._config['source']
        if isinstance(source, str) and len(source) == 42:
            source_address = source
        else:
            source_address = self._runner.get_node_address(source)

        extra_params = ''
        if 'target' in self._config:
            target = self._config['source']
            if isinstance(target, str) and len(target) == 42:
                target_address = target
            else:
                target_address = self._runner.get_node_address(target)
            extra_params = f'/{target_address}'

        params = dict(
            pfs_url=pfs_url,
            token_address=self._runner.token_address,
            source_address=source_address,
            extra_params=extra_params,
        )
        return params

    def _process_response(self, response_dict: dict):
        exp_request_count = self._config.get('request_count')
        if exp_request_count:
            actual_request_count = response_dict['request_count']
            if actual_request_count != exp_request_count:
                raise ScenarioAssertionError(
                    f'Expected request_count {exp_request_count} but got {actual_request_count}',
                )

        actual_routes_counts = [len(response['routes']) for response in response_dict['responses']]
        exp_routes_counts = self._config.get('routes_count')
        if exp_routes_counts:
            if isinstance(exp_routes_counts, int):
                request_count = exp_request_count if exp_request_count else 1
                exp_routes_counts = [exp_routes_counts] * request_count
            elif isinstance(exp_routes_counts, (list, tuple)):
                if len(exp_routes_counts) != len(actual_routes_counts):
                    raise ScenarioAssertionError(
                        f'Expected {len(exp_routes_counts)} routes but got '
                        f'{len(actual_routes_counts)}',
                    )

            loop_iterator = enumerate(zip(exp_routes_counts, actual_routes_counts))
            for i, (exp_route_count, actual_route_count) in loop_iterator:
                if exp_route_count != actual_route_count:
                    raise ScenarioAssertionError(
                        f'Expected route count {exp_route_count} but got {actual_route_count} '
                        f'at index {i}',
                    )

        actual_routes = [response['routes'] for response in response_dict['responses']]
        exp_routes = self._config.get('expected_routes')
        if exp_routes:
            if len(exp_routes) != len(actual_routes):
                raise ScenarioAssertionError(
                    f'Expected {len(exp_routes)} routes but got {len(actual_routes)}.',
                )
            for i, (exp_route, actual_route) in enumerate(zip(exp_routes, actual_routes)):
                if exp_route != actual_route:
                    raise ScenarioAssertionError(
                        f'Expected route {exp_route} but got {actual_route} at index {i}',
                    )
