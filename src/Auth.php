<?php
namespace Panadas\AuthPlugin;

use Panadas\Auth\Auth as BaseAuth;
use Panadas\Auth\Handler\HandlerInterface;
use Panadas\Auth\UserFinder\UserFinderInterface;
use Panadas\Event\Event;
use Panadas\Framework\Application;
use Panadas\Framework\ApplicationAwareInterface;
use Panadas\Framework\ApplicationAwareTrait;
use Panadas\HttpMessage\Cookie;

class Auth extends BaseAuth implements ApplicationAwareInterface
{

    use ApplicationAwareTrait;

    public function __construct(Application $application, UserFinderInterface $userFinder, HandlerInterface $handler)
    {
        parent::__construct($userFinder, $handler);

        $this->setApplication($application);

        $application
            ->before("handle", [$this, "beforeHandleEvent"])
            ->before("send", [$this, "beforeSendEvent"]);
    }

    public function beforeHandleEvent(Event $event)
    {
        $this->authenticate($event->getParams()->get("request"));

        $logger = $event->getPublisher()->getServices()->get("logger");
        if (null !== $logger) {
            if ($this->isAuthed()) {
                $logger->info("User is authenticated: {$this->getUser()->getId()}");
            } else {
                $logger->info("User is not authenticated");
            }
        }
    }

    public function beforeSendEvent(Event $event)
    {
        $params = $event->getParams();

        if (!$this->isCookieSecure() || $params->get("request")->isSecure()) {
            $this->applyCookie($params->get("response"));
        }
    }
}
