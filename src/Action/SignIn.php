<?php
namespace Panadas\AuthModule\Action;

use Panadas\Framework\Action\AbstractAction;
use Panadas\Framework\HttpMessage\HtmlResponse;
use Panadas\HttpMessage\Request;

class SignIn extends AbstractAction
{

    protected function before(Request $request)
    {
        $application = $this->getApplication();

        if ($application->getServices()->get("auth")->isAuthed()) {
            return $application->httpError403("You are already authenticated");
        }
    }

    protected function get(Request $request)
    {
        $response = new HtmlResponse($this->getApplication());

        if ($request->isPost()) {
            $response->setStatusCode(401);
        }

        return $response->render(
            '
                <div class="jumbotron">
                    <h1>Sign In</h1>
                </div>
                <form method="post" class="form-horizontal" role="form">
                    <div class="form-group">
                        <label for="username" class="col-sm-4 control-label">Username</label>
                        <div class="col-sm-4">
                            <input type="email" id="username" name="username" class="form-control">
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="password" class="col-sm-4 control-label">Password</label>
                        <div class="col-sm-4">
                            <input type="password" id="password" name="password" class="form-control">
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="col-sm-offset-4 col-sm-8">
                            <div class="checkbox">
                                <label><input type="checkbox" name="persist"> Remember me</label>
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="col-sm-offset-4 col-sm-8">
                            <button type="submit" class="btn btn-default">Sign in</button>
                        </div>
                    </div>
                </form>
            '
        );
    }

    protected function post(Request $request)
    {
        $application = $this->getApplication();

        $params = $request->getDataParams();

        if (!$params->has("username")) {
            return $application->httpError400("A username must be provided");
        }

        if (!$params->has("password")) {
            return $application->httpError400("A password must be provided");
        }

        $auth = $application->getServices()->get("auth");

        try {
            $token = $auth->signIn($params->get("username"), $params->get("password"));
        } catch (\InvalidArgumentException $exception) {
            return $application->httpError401("Invalid username or password");
        }

        return $application->redirect("/");
    }
}
