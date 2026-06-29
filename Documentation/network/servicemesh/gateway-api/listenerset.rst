.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _gs_gateway_listenerset:

*******************
ListenerSet Support
*******************

`ListenerSet <https://gateway-api.sigs.k8s.io/api-types/listenerset/>`__ allows
multiple teams to contribute listeners to a shared Gateway without editing the
Gateway itself. An infrastructure owner can manage the Gateway and its
infrastructure while application owners manage listeners, Routes, and TLS
certificates in their own namespaces.

ListenerSets are useful when you want to:

- Delegate listener and certificate ownership to application teams.
- Share one Gateway address and load-balancing infrastructure across teams.
- Split a large listener configuration across multiple resources.
- Configure more than the 64 listeners allowed in a single Gateway resource.

A ListenerSet has one parent Gateway, while a Gateway can accept multiple
ListenerSets. ListenerSet listeners use the parent Gateway's address and
infrastructure; a ListenerSet does not create a separate load balancer or
Gateway Service.

Before you begin
================

Cilium supports the Standard ``gateway.networking.k8s.io/v1`` ListenerSet API
from Gateway API v1.5.1. Complete the :ref:`Gateway API prerequisites
<gs_gateway_api>` and enable Cilium Gateway API support with
``gatewayAPI.enabled=true``. There is no separate Cilium ListenerSet flag.

The ListenerSet CRD must be installed before the Cilium operator starts so
that Cilium can detect it. If you add the CRD to an existing installation,
restart the Cilium operator. The operator logs the following message after it
detects the CRD:

.. code-block:: text

    ListenerSet CRD is installed, ListenerSet support is enabled

.. note::

    The parent Gateway must have at least one valid listener of its own. A
    valid ListenerSet does not make an otherwise invalid Gateway accepted.

Understand ListenerSet delegation
=================================

ListenerSet delegation has two independent permission boundaries:

#. The Gateway selects the namespaces from which ListenerSets may attach by
   using ``spec.allowedListeners.namespaces``.
#. Each listener in a ListenerSet selects the Routes that may attach by using
   ``allowedRoutes``.

A Gateway accepts no ListenerSets by default. The Gateway owner can configure
one of the following namespace policies:

.. list-table:: ListenerSet namespace policies
   :header-rows: 1

   * - Value
     - Behavior
   * - ``None``
     - Accept no ListenerSets. This is the default.
   * - ``Same``
     - Accept ListenerSets only from the Gateway's namespace.
   * - ``Selector``
     - Accept ListenerSets from namespaces matching a label selector.
   * - ``All``
     - Accept ListenerSets from every namespace.

Use ``Same`` for a Gateway managed by one namespace. Use ``Selector`` when
delegating access to a known set of application namespaces. Use ``All`` only
when every namespace should be able to propose listeners on the shared
Gateway.

When ``allowedRoutes`` is omitted from a ListenerSet listener, Routes are
allowed from the ListenerSet's namespace. This default is relative to the
ListenerSet, not to the parent Gateway.

The namespace in a ListenerSet's ``parentRef`` defaults to the ListenerSet's
namespace. Set it explicitly when the Gateway is in another namespace.
Cross-namespace ListenerSet attachment is authorized by ``allowedListeners``
and does not require a ``ReferenceGrant``.

Example: Delegate an HTTP listener
==================================

The following example creates a Gateway in the ``default`` namespace and
allows ListenerSets from namespaces with the ``gateway-access: "true"`` label.
The ``listenerset-demo`` namespace owns the ListenerSet, HTTPRoute, and backend
Service.

.. literalinclude:: ../../../../examples/kubernetes/gateway/listenerset.yaml
     :language: yaml

Apply the configuration and deploy the echo application in the delegated
namespace:

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/listenerset.yaml
    $ kubectl -n listenerset-demo apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/echo.yaml

Wait for the parent Gateway and ListenerSet to become programmed:

.. code-block:: shell-session

    $ kubectl get gateway shared-gateway
    NAME             CLASS    ADDRESS       PROGRAMMED   AGE
    shared-gateway   cilium   192.0.2.100   True         1m

    $ kubectl get listenerset -n listenerset-demo delegated-listeners
    NAME                  ACCEPTED   PROGRAMMED   AGE
    delegated-listeners   True       True         1m

Send a request to the delegated listener:

.. code-block:: shell-session

    $ GATEWAY=$(kubectl get gateway shared-gateway -o jsonpath='{.status.addresses[0].value}')
    $ curl --fail --header 'Host: echo.example.com' http://$GATEWAY/

Attach Routes to a ListenerSet
==============================

Routes attach directly to the resource that defines their listener. A Route
for a ListenerSet listener must specify ``kind: ListenerSet`` in its parent
reference. If the kind is omitted, it defaults to ``Gateway``.

The HTTPRoute in the preceding example attaches to only the ``echo`` listener:

.. code-block:: yaml

    parentRefs:
    - group: gateway.networking.k8s.io
      kind: ListenerSet
      name: delegated-listeners
      sectionName: echo

If ``sectionName`` and ``port`` are both omitted, the Route is considered for
all compatible listeners in the referenced ListenerSet. A Route that names
``shared-gateway`` instead does not attach to listeners defined in
``delegated-listeners``. A Route can contain separate parent references for a
Gateway and a ListenerSet, but the two attachments are evaluated and reported
independently. A Route parent reference without a namespace looks for its
parent in the Route's namespace.

Listener names must be unique within one Gateway or ListenerSet. They do not
need to be unique across the parent Gateway and all attached ListenerSets,
because ``sectionName`` applies only to the directly referenced resource.

Cilium supports the following listener and Route combinations:

.. list-table:: Compatible Route resources
   :header-rows: 1

   * - Listener protocol
     - Route resources
   * - HTTP or HTTPS
     - ``HTTPRoute`` and ``GRPCRoute``
   * - TLS passthrough
     - ``TLSRoute``
   * - TCP
     - ``TCPRoute``, when its optional CRD is installed
   * - UDP
     - ``UDPRoute``, when its optional CRD is installed

TLS termination on a listener with ``protocol: TLS`` is not supported. Use an
HTTPS listener for TLS termination, or a TLS listener for passthrough.

Example: Delegate a TLS certificate
===================================

Certificate references on a ListenerSet are evaluated from the ListenerSet's
namespace. A ListenerSet can reference a Secret in its own namespace without
a ``ReferenceGrant``. A Secret in another namespace requires a
``ReferenceGrant`` in the Secret's namespace.

The following example places the ListenerSet in ``listenerset-tls-demo`` and
the certificate Secret in ``listenerset-certificates``. The ReferenceGrant
allows ListenerSets from the application namespace to use only the named
Secret.

Create the namespaces, apply the Gateway API resources, and deploy the backend:

.. code-block:: shell-session

    $ kubectl create namespace listenerset-tls-demo
    $ kubectl label namespace listenerset-tls-demo gateway-access=true
    $ kubectl create namespace listenerset-certificates

.. literalinclude:: ../../../../examples/kubernetes/gateway/listenerset-tls.yaml
     :language: yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/listenerset-tls.yaml
    $ kubectl -n listenerset-tls-demo apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/echo.yaml

Create the referenced certificate Secret after the ListenerSet exists:

.. code-block:: shell-session

    $ openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout secure-example-com.key -out secure-example-com.crt \
        -subj '/CN=secure.example.com' \
        -addext 'subjectAltName=DNS:secure.example.com'
    $ kubectl create secret tls secure-example-com \
        -n listenerset-certificates \
        --key=secure-example-com.key --cert=secure-example-com.crt

After the Gateway receives an address, test the HTTPS listener:

.. code-block:: shell-session

    $ GATEWAY=$(kubectl get gateway shared-tls-gateway -o jsonpath='{.status.addresses[0].value}')
    $ curl --fail --insecure \
        --resolve secure.example.com:443:$GATEWAY \
        https://secure.example.com/

A ReferenceGrant for a Gateway is not inherited by its ListenerSets. Likewise,
a ReferenceGrant for a ListenerSet does not grant the parent Gateway access to
the same Secret.

Example: Observe a listener conflict
====================================

Cilium evaluates direct Gateway listeners and allowed ListenerSet listeners as
one combined configuration. A listener is rejected when its port, protocol,
or hostname conflicts with a higher-precedence listener.

Listener precedence is:

#. Listeners defined directly on the parent Gateway.
#. ListenerSets ordered by creation time, oldest first.
#. ListenerSets with the same creation time ordered by ``namespace/name``.

After applying the HTTP example, create another ListenerSet that claims the
same hostname and port. It also contains a non-conflicting listener:

.. literalinclude:: ../../../../examples/kubernetes/gateway/listenerset-conflict.yaml
     :language: yaml

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/listenerset-conflict.yaml

Because ``delegated-listeners`` is older, its ``echo.example.com`` listener
wins. The ``duplicate-echo`` listener receives ``Conflicted=True`` with the
``HostnameConflict`` reason, while the ``other`` listener can still be
accepted. The ListenerSet can therefore have top-level ``Accepted=True`` even
though one of its listeners was rejected.

Deleting and recreating a ListenerSet changes its creation time and can change
which listener wins a conflict. Avoid using precedence as the normal way to
coordinate teams; allocate ports and hostnames deliberately.

Operate and troubleshoot ListenerSets
=====================================

Check the parent Gateway, ListenerSet, and Route when troubleshooting:

.. code-block:: shell-session

    $ kubectl get gateway shared-gateway -o yaml
    $ kubectl get listenerset -n listenerset-demo delegated-listeners -o yaml
    $ kubectl get httproute -n listenerset-demo echo -o yaml

The resources report different parts of the overall state:

- The Gateway's ``status.attachedListenerSets`` field counts ListenerSets that
  contain at least one valid listener.
- The Gateway's ``status.listeners`` field contains only listeners defined
  directly on the Gateway.
- ListenerSet top-level ``Accepted`` and ``Programmed`` conditions summarize
  the ListenerSet. They do not guarantee that every listener was accepted.
- ListenerSet ``status.listeners`` entries report per-listener ``Accepted``,
  ``Programmed``, ``ResolvedRefs``, and ``Conflicted`` conditions, as well as
  ``attachedRoutes`` and ``supportedKinds``.
- Route status is reported independently for each parent reference. Inspect
  the entry whose parent kind is ``ListenerSet``.

A programmed ListenerSet does not replace checking the parent Gateway's
``Programmed`` condition and address. The Gateway owns the shared data-plane
infrastructure.

The following conditions and reasons identify common configuration problems:

.. list-table:: Common ListenerSet problems
   :header-rows: 1

   * - Status
     - Meaning
   * - ``Accepted=False``, reason ``NotAllowed``
     - The Gateway's ``allowedListeners`` policy does not select the
       ListenerSet namespace.
   * - ``Accepted=False``, reason ``ListenersNotValid``
     - The ListenerSet contains no valid listeners. Inspect each listener's
       conditions for the specific error.
   * - ``Conflicted=True``
     - A higher-precedence listener claims an incompatible port, protocol, or
       hostname.
   * - ``ResolvedRefs=False``, reason ``RefNotPermitted``
     - A cross-namespace certificate reference lacks a ListenerSet-specific
       ReferenceGrant.
   * - ``ResolvedRefs=False``, reason ``InvalidRouteKinds``
     - ``allowedRoutes.kinds`` includes a Route kind that is not compatible
       with the listener protocol. If none of the kinds are compatible, the
       listener is invalid.
   * - Route ``Accepted=False``, reason ``NotAllowedByListeners``
     - The listener's ``allowedRoutes`` policy does not allow that Route kind
       or namespace.

You can confirm that the operator detected the ListenerSet CRD by checking its
logs:

.. code-block:: shell-session

    $ kubectl logs -n kube-system deployment/cilium-operator | grep ListenerSet

Plan for shared infrastructure
==============================

All ListenerSets attached to a Gateway share its address, generated Service,
and infrastructure settings. Changes to the Gateway can therefore affect every
attached ListenerSet. Conversely, deleting a ListenerSet removes its listeners
from the shared Gateway without deleting the Gateway itself.

Each ListenerSet can contain up to 64 listeners. Multiple ListenerSets can be
used to scale beyond the 64-listener limit of a single Gateway resource. When
several teams share a Gateway, establish ownership rules for ports, hostnames,
and certificate Secrets so that configuration conflicts are exceptional rather
than expected.

For the complete attachment, conflict, and status semantics, see the upstream
`ListenerSet documentation
<https://gateway-api.sigs.k8s.io/api-types/listenerset/>`__ and
`GEP-1713 <https://gateway-api.sigs.k8s.io/geps/gep-1713/>`__.
