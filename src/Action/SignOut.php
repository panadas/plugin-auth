<?php
namespace Panadas\AuthPlugin\Action;

use Panadas\Framework\Action\AbstractAction;
use Panadas\HttpMessage\Request;

class SignOut extends AbstractAction
{

    protected function before(Request $request)
    {
        $application = $this->getApplication();

        if (!$application->getServices()->get("auth")->isAuthed()) {
            return $application->httpError403("You are not authenticated");
        }
    }

    protected function get(Request $request)
    {
        $application = $this->getApplication();

        $application->getServices()->get("auth")->signOut();

        return $application->redirect("/");
    }

    protected function post(Request $request)
    {
        return $this->get($request);
    }
}
