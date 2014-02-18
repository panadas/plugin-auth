<?php
namespace Panadas\AuthModule;

use Panadas\AuthManager\Auth as BaseAuth;
use Panadas\EventManager\Event;
use Panadas\Framework\Application;
use Panadas\Framework\ApplicationAwareInterface;
use Panadas\Framework\ApplicationAwareTrait;
use Panadas\HttpMessage\Cookie;
use Panadas\AuthManager\UserFinder\UserFinderInterface;
use Panadas\AuthManager\Handler\HandlerInterface;

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
