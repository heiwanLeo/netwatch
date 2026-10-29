"""Explainable 0..100 quality scores. Failed attempts never become zero-latency samples."""
import math
import statistics

def metrics(values, attempts, failures):
    v=sorted(x for x in values if isinstance(x,(float,int)) and math.isfinite(x))
    return {'mean':statistics.mean(v) if v else None,'p95':v[max(0,math.ceil(len(v)*.95)-1)] if v else None,
            'stddev':statistics.pstdev(v) if v else None,'attempts':attempts,'failure_rate':100*failures/attempts if attempts else None}

def quality_score(stats, kind='direct', minimum=5):
    ranges={'direct':{'mean':(50,800),'stddev':(15,400),'p95':(100,1600)},
            'vpn':{'mean':(200,1800),'stddev':(40,650),'p95':(400,3000)}}[kind]
    def descending(value, bounds):
        if value is None:return 0
        lo,hi=bounds
        return round(max(0,min(100,100*(hi-value)/(hi-lo))),1)
    parts=[{'name':'成功率','weight':40,'score':round(100-(stats.get('failure_rate') or 0),1)},
           {'name':'平均延迟','weight':25,'score':descending(stats.get('mean'),ranges['mean'])},
           {'name':'波动','weight':20,'score':descending(stats.get('stddev'),ranges['stddev'])},
           {'name':'P95','weight':15,'score':descending(stats.get('p95'),ranges['p95'])}]
    count=stats.get('attempts',0)
    return {'score':round(sum(p['weight']*p['score']/100 for p in parts)) if count>=minimum else None,
            'parts':parts,'samples':count,'ready':count>=minimum,'minimum':minimum}

def node_estimate(delay):
    return quality_score(metrics([delay] if delay is not None else [],1,int(delay is None)), 'vpn',minimum=1)


def should_switch(current,candidate,bad_count,elapsed,cooldown,threshold):
    return (current is not None and candidate is not None and current<threshold and bad_count>=2
            and elapsed>=cooldown and candidate>=max(threshold,current+10))
