<?php

namespace App\Controller\Api;

use App\Entity\User;
use App\Service\MySlugger;
use App\Repository\UserRepository;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;


class UserController extends AbstractController
{
    /**
     * Get information artist and exhibitions for profile page
     * 
     * @return Response
     * @Route("api/secure/users/profile", name="app_api_users_profile", methods={"GET"})
     */
    public function getInformationForProfile(CsrfTokenManagerInterface $csrfTokenManager): Response
    {
        // getting the logged user
        /** @var \App\Entity\User $user */
        $user = $this->getUser();

        
        //fetching information about logged user
        $nickname = $user->getNickname();
        $firstname = $user->getFirstname();
        $lastname = $user->getLastname();
        $email = $user->getEmail();
        $avatar = $user->getAvatar();
        $presentation = $user->getPresentation();
        $dateOfBirth = $user->getDateOfBirth();
        $role = $user->getRoles();
        
        //fetching exhibitions of user
        $exhibitionFetched = $user->getExhibition();
        
        //declaring an empty array
        $exhibitions = [];
        
        //loop on each exhibition
        foreach ($exhibitionFetched as $exhibition) {
            $id = $exhibition->getId();
            $title = $exhibition->getTitle();
            $description = $exhibition->getDescription();
            $exhibitions[] = [
                'id' => $id,
                'title' => $title,
                'description' => $description
            ];
        }
        
        $favorites = $user->getFavorites();
        $favoritesArray =[];
        foreach($favorites as $favorite)
        {
            
            $id = $favorite->getId();
            $favoritesArray[] = $id;
        }

        $csrfToken = $csrfTokenManager->getToken('csrfToken')->getValue();
        $cookie = Cookie::create('csrfToken', $csrfToken);
     
        // setting an empty array
        $data = [];

        // putting the informations in the empty array
        $data = [
            'nickname' => $nickname,
            'firstname' => $firstname,
            'lastname' => $lastname,
            'email' => $email,
            'birthday' => $dateOfBirth,
            'avatar' => $avatar,
            'presentation' => $presentation,
            'role' => $role,
            'exhibitions' => $exhibitions,
            'favorites' => $favoritesArray,
        ];

        //sending the response with all data
        $response = $this->json($data, Response::HTTP_OK);
        $response->headers->setCookie($cookie);
        return $response;
    }

    /**
     * Create a new user
     *
     * @param Request $request
     * @param SerializerInterface $serializer
     * @param ValidatorInterface $validator
     * @param ManagerRegistry $doctrine
     * @param UserPasswordHasherInterface $passwordHasher
     * @param MySlugger $slugger
     * @param UserRepository $userRepository
     * @return Response
     * @Route ("api/users/new", name="app_api_users_create", methods={"POST"})
     */
    public function createUser(Request $request, SerializerInterface $serializer, ValidatorInterface $validator, ManagerRegistry $doctrine, UserPasswordHasherInterface $passwordHasher, MySlugger $slugger, UserRepository $userRepository): Response
    {

        //Fetch the json content
        $jsonContent = $request->getContent();

        // Checking if json format is respected
        //if not, throw an error
        try {
            //Transforming json Content into entity
            $user = $serializer->deserialize($jsonContent, User::class, 'json');
        } catch (NotEncodableValueException $e) {

            return $this->json(
                ['error' => 'JSON INVALIDE'],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        //checking if email aleady exist in DB
        if ($userRepository->findOneByEmail($user->getEmail()) !== null) {
            return $this->json(
                ['erreur' => 'L\'email est déjà existant'],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        // Checking the entity : if all fields are well fill
        $errors = $validator->validate($user);

        //Checking if there is any error
        // If yes, then throw an error
        if (count($errors) > 0) {
            // return array
            $errorsClean = [];
            // @Clean error messages
            /** @var ConstraintViolation $error */
            foreach ($errors as $error) {
                $errorsClean[$error->getPropertyPath()][] = $error->getMessage();
            };

            return $this->json($errorsClean, Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        //hashing the password
        $user->setPassword($passwordHasher->hashPassword($user, $user->getPassword()));

        //Saving the entity and saving in DBB
        $entityManager = $doctrine->getManager();
        $entityManager->persist($user);
        $entityManager->flush();

        //Return response 201 if created
        return $this->json(
            [],
            Response::HTTP_CREATED,
        );
    }

    /**
     * Edit profile
     *
     * @param Request $request
     * @param SerializerInterface $serializer
     * @param ValidatorInterface $validator
     * @param ManagerRegistry $doctrine
     * @return Response
     * @Route("api/secure/users/edit", name="app_api_user_edit", methods={"PATCH"})
     */
    public function editUser(Request $request, SerializerInterface $serializer, ValidatorInterface $validator, ManagerRegistry $doctrine, CsrfTokenManagerInterface $csrfTokenManager): Response
    {

        // getting the logged user
        /** @var \App\Entity\User $user */
        $user = $this->getUser();

        // Récupérer le token CSRF envoyé dans la requête
        $submittedtoken = $request->cookies->get('csrfToken');

        // Vérifier le token CSRF
        if (!$csrfTokenManager->isTokenValid(new CsrfToken('csrfToken', $submittedtoken))) {
            throw new AccessDeniedHttpException('Invalid CSRF token');
        }

        //Get Json content
        $jsonContent = $request->getContent();

        try {
            // Convert Json in doctrine entity
            $userNewInfos = $serializer->deserialize($jsonContent, User::class, 'json', ['object_to_populate' => $user]);
        } catch (NotEncodableValueException $e) {
            // if json getted isn't right, make an alert for client
            return $this->json(
                ['error' => 'JSON invalide'],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        //Validate entity
        $errors = $validator->validate($userNewInfos, null, ['registration']);

        // Is there some errors ?
        if (count($errors) > 0) {
            //returned array
            $errorsClean = [];
            // @get back validation errors clean
            /** @var ConstraintViolation $error */
            foreach ($errors as $error) {
                $errorsClean[$error->getPropertyPath()][] = $error->getMessage();
            };

            return $this->json($errorsClean, Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // Save entity
        $entityManager = $doctrine->getManager();
        $entityManager->persist($user);
        $entityManager->flush();

        // return status 200
        return $this->json(
            $user,
            Response::HTTP_OK,
            [],
            ['groups' => 'get_user']
        );
    }
}
