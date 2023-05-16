<?php

namespace App\Controller\Api;

use App\Entity\Artwork;
use App\Entity\Exhibition;
use App\Repository\ArtworkRepository;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;


class ArtworkController extends AbstractController
{
    /**
     * Create an artwork entity
     *
     * @param Request $request
     * @param ManagerRegistry $doctrine
     * @param SerializerInterface $serializer
     * @param ValidatorInterface $validator
     * @return Response
     * @Route("/api/secure/artworks/new", name="app_api_artwork_new", methods={"POST"})
     */
    public function createArtwork(Request $request, ManagerRegistry $doctrine, SerializerInterface $serializer, ValidatorInterface $validator): Response
    {
        //Fetch the json content
        $jsonContent = $request->getContent();


        // Checking if json format is respected
        //if not, throw an error
        try {
            //Transforming json Content into entity
            $artwork = $serializer->deserialize($jsonContent, Artwork::class, 'json');
        } catch (NotEncodableValueException $e) {

            return $this->json(
                ['error' => 'JSON INVALIDE'],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        // Checking the entity : if all fields are well fill
        $errors = $validator->validate($artwork);

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

        // fetching exhibition
        $exhibitionToDisplay = $artwork->getExhibition();

        //Saving the entity and saving in DBB
        $entityManager = $doctrine->getManager();
        $entityManager->persist($artwork);
        $entityManager->flush();


        //Return response if created
        return $this->json(
            $exhibitionToDisplay->getArtwork(),
            Response::HTTP_CREATED,
            [],
            ['groups' => 'get_artwork_by_exhibition']
        );
    }

    /**
     * Edit artwork entity
     *
     * @param Request $request
     * @param ManagerRegistry $doctrine
     * @param SerializerInterface $serializer
     * @param ValidatorInterface $validator
     * @param Artwork|null $artworkToEdit
     * @return Response
     * @Route("api/secure/artworks/{id}/edit", name="app_api_artwork_edit", requirements={"id"="\d+"}, methods={"PATCH"})
     */
    public function editArtwork(Request $request, ManagerRegistry $doctrine, SerializerInterface $serializer, ValidatorInterface $validator, Artwork $artworkToEdit = null): Response
    {

        // 404 ?
        if ($artworkToEdit === null) {
            return $this->json(['error' => 'Oeuvre non trouvé.'], Response::HTTP_NOT_FOUND);
        }
        //Fetch the json content
        $jsonContent = $request->getContent();

        // Checking if json format is respected
        //if not, throw an error
        try {
            //Transforming json Content into entity 
            $artworkModified = $serializer->deserialize($jsonContent, Artwork::class, 'json', ['object_to_populate' => $artworkToEdit]);
        } catch (NotEncodableValueException $e) {

            return $this->json(
                ['error' => 'JSON INVALIDE'],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        // Checking the entity : if all fields are well fill
        $errors = $validator->validate($artworkModified);

        //Checking if there is any error
        // If yes, then throw an error
        if (count($errors) > 0) {
            // return array
            $errorsClean = [];
            // Clean error messages
            /** @var ConstraintViolation $error */
            foreach ($errors as $error) {
                $errorsClean[$error->getPropertyPath()][] = $error->getMessage();
            };

            return $this->json($errorsClean, Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        //Saving the entity and saving in DBB
        $entityManager = $doctrine->getManager();

        // sending new data in DB
        $entityManager->persist($artworkModified);
        $entityManager->flush();

        //Return response if created
        return $this->json(
            $artworkModified,
            Response::HTTP_OK,
            [],
            ['groups' => 'get_artwork_by_exhibition']
        );
    }

    /**
     * Remove an entity
     *
     * @param Artwork|null $artwork
     * @param EntityManagerInterface $entityManager
     * @return Response
     * @Route("api/secure/artworks/{id}/delete", name="app_api_artwork_delete",requirements={"id"="\d+"}, methods={"DELETE"})
     */
    public function deleteArtwork(Artwork $artwork = null, EntityManagerInterface $entityManager): Response
    {

        //404?
        if ($artwork === null) {
            return $this->json(['error' => 'Oeuvre non trouvé.'], Response::HTTP_NOT_FOUND);
        }

        //fetch exhibiton depending on artwork
        $exhibition = $artwork->getExhibition();
        // remove entity artwork
        $entityManager->remove($artwork);
        $entityManager->flush();

        //fetch artworks of the exhibition
        $newArtworksList = $exhibition->getArtwork();

        //return response 
        return $this->json(
            $newArtworksList,
            Response::HTTP_NO_CONTENT,
        );
    }

    /**
     * Get artworks by exhibition for profile page
     *
     * @param Exhibition|null $exhibition
     * @param ArtworkRepository $artworkRepository
     * @return Response 
     * @Route("api/secure/artworks/exhibitions/{id}/profile", name="app_api_artwork_profile",requirements={"id"="\d+"}, methods={"GET"})
     */
    public function getArtworksByExhibition(Exhibition $exhibition = null, ArtworkRepository $artworkRepository): Response
    {
        //404
        if ($exhibition === null) {
            return $this->json(['error' => 'Exposition non trouvé.'], Response::HTTP_NOT_FOUND);
        }

        // fetching exhibitons for profile page
        $artworksList = $artworkRepository->findBy(['exhibition' => $exhibition], ['title' => 'asc']);

        // return status 200
        return $this->json($artworksList, Response::HTTP_OK, [], ['groups' => 'get_artwork_by_exhibition']);
    }
}
