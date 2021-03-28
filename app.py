import argparse
import time
import typing as tp

from flask import Flask, request, jsonify

import Dns

from IpRecord import IpRecord
from IpRecordCache import IpRecordCache
from Trace import Trace

app = Flask(__name__)

domain_cache: tp.Optional[IpRecordCache] = None


def get_cache() -> IpRecordCache:
    global domain_cache
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-factor", type=int, default=50)
    args = parser.parse_args()

    if domain_cache is None:
        domain_cache = IpRecordCache(records_to_cache=args.cache_factor)

    return domain_cache


@app.route('/get-a-records', methods=['GET'])
def get_records():
    trace = request.args.get('trace') == "true"

    domain = request.args.get('domain')
    if domain is None:
        return 'Domain is missing', 400

    domain = domain.split("/")[0]

    try:
        get_cache()

        response: tp.Optional[IpRecord] = None
        if not trace:
            response = domain_cache[domain]
            if response is not None and response.expires_at < time.time():
                response = None

        if response is not None:
            print(f"Using cache for {domain}")
            return jsonify(
                domain=domain,
                ips=response.ips,
                ttl=max(response.expires_at - time.time(), 0),
            )

        data_trace = Trace()
        response = Dns.find_recursive(domain, Dns.ROOT_SERVERS_DNS, data_trace)
    except Exception as e:
        print(e)
        response = None

    if response is None:
        return jsonify(
            error='Domain is not resolved',
            trace=data_trace.compose()
        ), 404

    domain_cache[domain] = response

    if trace:
        return jsonify(
            domain=domain,
            ips=response.ips,
            ttl=max(response.expires_at - time.time(), 0),
            trace=data_trace.compose(),
            exact_match=any([d.startswith(domain) for d, _ in response.ips])
        )
    else:
        return jsonify(
            domain=domain,
            ips=response.ips,
            ttl=max(response.expires_at - time.time(), 0),
            exact_match=any([d.startswith(domain) for d, _ in response.ips])
        )


if __name__ == '__main__':
    app.run()
