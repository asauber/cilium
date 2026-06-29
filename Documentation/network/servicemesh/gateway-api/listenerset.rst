.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_listenerset:

*******************
ListenerSet Support
*******************

`ListenerSet <https://gateway-api.sigs.k8s.io/geps/gep-1713/>`__ allows
listeners from one or more resources to attach to a single Gateway. This lets
an infrastructure owner manage the Gateway while application owners manage
their listeners and TLS certificates in separate namespaces. All attached
listeners use the parent Gateway's address and infrastructure.

Cilium supports the Standard ``gateway.networking.k8s.io/v1`` ListenerSet API
from Gateway API v1.5.1. There is no separate Cilium feature flag. The
ListenerSet CRD must be installed before the Cilium operator starts so that
Cilium can detect it. If you install the CRD later, restart the operator.

.. note::

    A Gateway does not accept ListenerSets by default. Configure
    ``spec.allowedListeners`` on the Gateway to select the namespaces from
    which ListenerSets may attach.

Delegate a listener
===================

The following example creates a Gateway in the ``default`` namespace and
allows ListenerSets from namespaces with the ``gateway-access: "true"`` label.
The ListenerSet and its HTTPRoute are owned by the ``listenerset-demo``
namespace.

.. literalinclude:: ../../../../examples/kubernetes/gateway/listenerset.yaml
     :language: yaml

Apply the configuration and deploy the echo application in the delegated
namespace:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/listenerset.yaml
    $ kubectl -n listenerset-demo apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/echo.yaml

Routes attach directly to the resource that defines their listener. The
HTTPRoute in this example therefore specifies ``kind: ListenerSet`` and names
the ``echo`` listener with ``sectionName``. A Route that references
``shared-gateway`` instead does not attach to listeners defined by
``delegated-listeners``.

Verify the ListenerSet
======================

Check both the parent Gateway and the ListenerSet:

.. code-block:: shell-session

    $ kubectl get gateway shared-gateway
    NAME             CLASS    ADDRESS          PROGRAMMED   AGE
    shared-gateway   cilium   192.0.2.100      True         1m

    $ kubectl get listenerset -n listenerset-demo delegated-listeners
    NAME                  ACCEPTED   PROGRAMMED   AGE
    delegated-listeners   True       True         1m

Send a request to the listener after the Gateway receives an address:

.. code-block:: shell-session

    $ GATEWAY=$(kubectl get gateway shared-gateway -o jsonpath='{.status.addresses[0].value}')
    $ curl --fail --header 'Host: echo.example.com' http://$GATEWAY/

The Gateway's ``status.attachedListenerSets`` field reports the number of
attached ListenerSets that contain at least one valid listener. Detailed
status for delegated listeners is reported in the ListenerSet's
``status.listeners`` field, not in the parent Gateway's ``status.listeners``.
Inspect the per-listener ``Accepted``, ``Programmed``, ``ResolvedRefs``, and
``Conflicted`` conditions when troubleshooting. A programmed ListenerSet does
not replace checking the parent Gateway's ``Programmed`` condition and address.

Operational considerations
==========================

- The Gateway controls which ListenerSet namespaces are accepted with
  ``allowedListeners``. Its default value allows no ListenerSets.
- Each ListenerSet listener independently controls Route attachment with
  ``allowedRoutes``. When omitted, Routes are allowed from the ListenerSet's
  own namespace.
- A Route parent reference must explicitly set ``kind: ListenerSet``. If the
  kind is omitted, it defaults to ``Gateway``.
- ``HTTPRoute``, ``GRPCRoute``, ``TLSRoute``, and the optional ``TCPRoute`` and
  ``UDPRoute`` APIs can target compatible listeners in a ListenerSet.
- Listeners defined directly on the Gateway take precedence over conflicting
  ListenerSet listeners. Among ListenerSets, older resources take precedence.
  Conflicts are reported on the lower-precedence listener.
- A ListenerSet with a mixture of valid and invalid listeners can be accepted.
  Check each listener's status instead of relying only on the ListenerSet's
  top-level conditions.
- Certificate references are evaluated from the ListenerSet's namespace. A
  cross-namespace Secret requires a ``ReferenceGrant`` for the ListenerSet;
  grants made to the parent Gateway are not inherited.
- The parent Gateway must retain at least one valid listener of its own. A
  valid ListenerSet does not make an otherwise invalid Gateway accepted.

See the upstream `ListenerSet documentation
<https://gateway-api.sigs.k8s.io/api-types/listenerset/>`__ for complete
attachment, conflict, and status semantics.
