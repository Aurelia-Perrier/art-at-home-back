<?php

namespace App\Controller\Api;

use App\Entity\Exhibition;
use App\Repository\ExhibitionRepository;
use Doctrine\Persistence\ManagerRegistry;
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

class ExhibitionController extends AbstractController
{
    /**
     * Get all exhibitions with related artworks and related artist
     *
     * @param ExhibitionRepository $exhibitionRepository
     * @return Response
     * @Route("/api/exhibitions", name="app_api_exhibitions_get", methods={"GET"})
     */
    public function getExhibitions(ExhibitionRepository $exhibitionRepository): Response
    {
        //fetching all exhibitions
        $exhibitionsList = $exhibitionRepository->findBy(['status' => 1]);

        // return status 200
        return $this->json($exhibitionsList, Response::HTTP_OK, [], ['groups' => 'get_exhibitions_collection']);
    }

    /**
     * Create exhibition item
     *
     * @param Request $request
     * @param SerializerInterface $serializer
     * @param ManagerRegistry $doctrine
     * @param ValidatorInterface $validator
     * @return Response
     * @Route("/api/secure/exhibitions/new", name="app_api_exhibition_new", methods={"POST"})
     */
    public function createExhibition(Request $request, SerializerInterface $serializer, ManagerRegistry $doctrine, ValidatorInterface $validator, CsrfTokenManagerInterface $csrfTokenManager): Response
    {

        /** @var \App\Entity\User $user */
        $user = $this->getUser();

        // Get CSRF Token
        $submittedtoken = $request->cookies->get('csrfToken');

        // Check CSRF Token
        if (!$csrfTokenManager->isTokenValid(new CsrfToken('csrfToken', $submittedtoken))) {
            throw new AccessDeniedHttpException('Invalid CSRF token');
        }

        //Get Json content
        $jsonContent = $request->getContent();

        try {
            // Convert Json in doctrine entity
            $exhibition = $serializer->deserialize($jsonContent, Exhibition::class, 'json');
        } catch (NotEncodableValueException $e) {
            // if json getted isn't right, make an alert for client
            return $this->json(
                ['error' => 'JSON invalide'],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        //Validate entity
        $errors = $validator->validate($exhibition);

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

        //setting the artist thanks to logged user
        $exhibition->setArtist($user);

        // Save entity
        $entityManager = $doctrine->getManager();
        $entityManager->persist($exhibition);
        $entityManager->flush();

        // return status 201
        return $this->json(
            $user->getExhibition(),
            Response::HTTP_CREATED,
            [],
            ['groups' => 'get_exhibitions_collection']
        );
    }
}
