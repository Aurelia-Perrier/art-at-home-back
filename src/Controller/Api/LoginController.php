<?php

namespace App\Controller\Api;

use App\Repository\UserRepository;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\JWTUserToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class LoginController extends AbstractController
{
    private $jwtManager;
    private $tokenStorage;
    private $passwordHasher;
    private $userRepository;

    public function __construct(JWTTokenManagerInterface $jwtManager, TokenStorageInterface $tokenStorage, UserPasswordHasherInterface $passwordHasher, UserRepository $userRepository)
    {
        $this->jwtManager = $jwtManager;
        $this->tokenStorage = $tokenStorage;
        $this->passwordHasher = $passwordHasher;
        $this->userRepository = $userRepository;
    }
    /**
     * @Route("/api/login", methods={"POST"})
     */
    public function login(Request $request)
    {
        $data = json_decode($request->getContent(), true);
        $email = $data['username'];
        $password = $data['password'];

        // Votre logique d'authentification
        $user = $this->userRepository->findOneBy(['email' => $email]);
        if (!$user || !$this->passwordHasher->isPasswordValid($user, $password)) {
            throw new AuthenticationException('Le mot de passe ou l\'email est invalide');
        }

        // Génération du jeton JWT
        $jwtToken = $this->jwtManager->create($user);

        // Configuration du cookie sécurisé
        $cookie = Cookie::create('jwtToken', $jwtToken)
            ->withHttpOnly(true)
            ->withSameSite('Strict')
            ->withSecure(true);

        // Stockage du jeton JWT dans le TokenStorage
        $token = new JWTUserToken($user->getRoles(), $user, $jwtToken);
        $this->tokenStorage->setToken($token);

        // Création de la réponse avec le cookie sécurisé
        $response = new Response();
        $response->headers->setCookie($cookie);
        return $response;
    }
}