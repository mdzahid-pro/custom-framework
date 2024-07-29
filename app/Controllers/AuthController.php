<?php

declare(strict_types = 1);

namespace App\Controllers;

use App\Contracts\AuthInterface;
use App\Contracts\RequestValidatorFactoryInterface;
use App\DataObjects\RegisterUserData;
use App\Enum\AuthAttemptStatus;
use App\Exception\ValidationException;
use App\RequestValidators\RegisterUserRequestValidator;
use App\RequestValidators\TwoFactorLoginRequestValidator;
use App\RequestValidators\UserLoginRequestValidator;
use App\ResponseFormatter;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Slim\Views\Twig;

class AuthController
{
    // Dependency Injection for the class constructor
    public function __construct(
        private readonly Twig $twig,
        private readonly RequestValidatorFactoryInterface $requestValidatorFactory,
        private readonly AuthInterface $auth,
        private readonly ResponseFormatter $responseFormatter
    ) {
    }

    // Render the login view
    public function loginView(Response $response): Response
    {
        return $this->twig->render($response, 'auth/login.twig');
    }

    // Render the register view
    public function registerView(Response $response): Response
    {
        return $this->twig->render($response, 'auth/register.twig');
    }

    // Handle user registration
    public function register(Request $request, Response $response): Response
    {
        // Validate the request data
        $data = $this->requestValidatorFactory->make(RegisterUserRequestValidator::class)->validate(
            $request->getParsedBody()
        );

        // Register the user with the validated data
        $this->auth->register(
            new RegisterUserData($data['name'], $data['email'], $data['password'])
        );

        // Redirect to the home page after registration
        return $response->withHeader('Location', '/')->withStatus(302);
    }

    // Handle user login
    public function logIn(Request $request, Response $response): Response
    {
        // Validate the request data
        $data = $this->requestValidatorFactory->make(UserLoginRequestValidator::class)->validate(
            $request->getParsedBody()
        );

        // Attempt to log the user in
        $status = $this->auth->attemptLogin($data);

        // Handle login failure
        if ($status === AuthAttemptStatus::FAILED) {
            throw new ValidationException(['password' => ['You have entered an invalid username or password']]);
        }

        // Handle two-factor authentication
        if ($status === AuthAttemptStatus::TWO_FACTOR_AUTH) {
            return $this->responseFormatter->asJson($response, ['two_factor' => true]);
        }

        // Return an empty JSON response on successful login
        return $this->responseFormatter->asJson($response, []);
    }

    // Handle user logout
    public function logOut(Response $response): Response
    {
        // Log the user out
        $this->auth->logOut();

        // Redirect to the home page after logout
        return $response->withHeader('Location', '/')->withStatus(302);
    }

    // Handle two-factor authentication login
    public function twoFactorLogin(Request $request, Response $response): Response
    {
        // Validate the request data
        $data = $this->requestValidatorFactory->make(TwoFactorLoginRequestValidator::class)->validate(
            $request->getParsedBody()
        );

        // Attempt two-factor login and handle failure
        if (! $this->auth->attemptTwoFactorLogin($data)) {
            throw new ValidationException(['code' => ['Invalid Code']]);
        }

        // Return the response on successful two-factor login
        return $response;
    }
}
