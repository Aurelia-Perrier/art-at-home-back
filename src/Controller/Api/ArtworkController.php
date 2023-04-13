<?php

namespace App\Controller\Api;

use App\Entity\Artwork;
use App\Repository\ArtworkRepository;
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
     * Get all artworks entity
     * @Route("/api/artworks", name="app_api_artwork", methods={"GET"})
     */
    public function getArtworks(ArtworkRepository $artworkRepository): Response
    {
        // fetch all artworks
        $artworks = $artworkRepository->findAll();

        // transform data in json format
        return $this->json(
            $artworks, 
            Response::HTTP_OK,
            [],
            ['groups' => 'get_artworks_collection']
        );
    }

    /**
     * Get on artwork entity
     *
     * @Route("/api/artworks/{id}", name="app_api_artwork_by_id", requirements={"id"="\d+"}, methods={"GET"})
     */
    public function getArtworkById(Artwork $artwork): Response
    {

        // transform entity Artwork into json 
        return $this->json(
            $artwork,
            Response::HTTP_OK,
            [],
            ['groups' => 'get_artwork']
        );

    }

    /**
     * Create an artwork entity
     *
     * @Route("/api/artworks/new", name="app_api_artwork_new", methods={"POST"})
     */
    public function createArtwork(Request $request, ManagerRegistry $doctrine, SerializerInterface $serializer, ValidatorInterface $validator) : Response
    {
        //Fetch the json content
        $jsonContent = $request->getContent();

        
        // Checking if json format is respected
        //if not, throw an error
        try{
            //On déserialise le json en entité
            $artwork = $serializer->deserialize($jsonContent, Artwork::class, 'json');
            

        }catch(NotEncodableValueException $e) {

            return $this->json(
                ['error' => 'JSON INVALIDE'],
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        // Checking the entity : if all fields are well fill
        
        $errors = $validator->validate($artwork);

        //Checking if there is any error
        // If yes, then throw an error
        if(count($errors) > 0)
        {
            return $this->json(
                $errors,
                Response::HTTP_UNPROCESSABLE_ENTITY
            );
        }

        //Saving the entity and saving in DBB
        $entityManager = $doctrine->getManager();
        $entityManager->persist($artwork);
        $entityManager->flush();

        //Return response if created
        return $this->json(
            $artwork, 
            Response::HTTP_CREATED,
            [],
            ['groups' => 'get_artwork']
        );
    }
    
    /**
     * Edit artwork entity
     *
     * @Route("api/artworks/{id}/edit", name="app_api_artwork_edit", requirements={"id"="\d+"}, methods={"POST"})
     */
    public function editArtwork() : Response
    {

        
    }


}