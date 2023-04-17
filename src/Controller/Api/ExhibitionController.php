<?php

namespace App\Controller\Api;

use App\Entity\Exhibition;
use App\Entity\User;
use App\Repository\ExhibitionRepository;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\Persistence\ManagerRegistry;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Serializer\SerializerInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Serializer\Exception\NotEncodableValueException;

class ExhibitionController extends AbstractController
{
    /**
     * Get all exhibitions 
     *@Route("/api/exhibitions", name="api_exhibitions_get", methods={"GET"})
     */
    public function getExhibitions(ExhibitionRepository $exhibitionRepository): Response
    {
        $exhibitionsList = $exhibitionRepository->findAll();

        return $this->json($exhibitionsList, Response::HTTP_OK, [], ['groups' => 'get_exhibitions_collection']);
    }

    /**
     * Get one exhibition
     * @Route("/api/exhibitions/{id<\d+>}", name="api_exhibition_by_id", methods={"GET"})
     */
    public function getExhibitionById(Exhibition $exhibition): Response
    {
        

        return $this->json($exhibition, Response::HTTP_OK, [], ['groups' => 'get_exhibition_by_id']);
    }

    /**
     * Create  exhibition item
     * @Route("/api/exhibitions/new", name="api_exhibition_new", methods={"PUT"})
     */
    public function createExhibition(Request $request, SerializerInterface $serializer,ManagerRegistry $doctrine, ValidatorInterface $validator)
    {
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

       // Save entity
       $entityManager = $doctrine->getManager();
       $entityManager->persist($exhibition);
       $entityManager->flush();

       // On retourne la réponse adaptée (201 + Location: URL de la ressource)
       return $this->json(
        // Le film créé peut être ajouté au retour
        $exhibition,
        // Le status code : 201 CREATED
        // utilisons les constantes de classes !
        Response::HTTP_CREATED,
        // REST ask an header Location + URL 
        [
            // if we need header location uncomment this :
            // 'Location' => $this->generateUrl('api_exhibition_by_id', ['id' => $exhibition->getId()])
        ],
        // Groups
        ['groups' => 'get_exhibition_by_id']
        );
    }

    /**
     * Edit exhibition item
     * @Route("/api/exhibitions/{id<\d+>}/edit", name="api_exhibition_edit", methods={"PUT"})
     */
    public function editExhibition(Exhibition $exhibitionToEdit, Request $request, SerializerInterface $serializer,ManagerRegistry $doctrine, ValidatorInterface $validator)
    {
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

        $exhibitionToEdit->setTitle($exhibition->getTitle());
        $exhibitionToEdit->setDescription($exhibition->getDescription());
        $exhibitionToEdit->setArtist($exhibition->getArtist());
        
        // Save entity
        $entityManager = $doctrine->getManager();
        $entityManager->persist($exhibitionToEdit);
        $entityManager->flush();

        
        return $this->json(
        
        $exhibitionToEdit,
        // status code : 200 HTTP_OK        
        Response::HTTP_OK,
        // REST ask an header Location + URL 
        [
            // if we need header location uncomment this :
            // 'Location' => $this->generateUrl('api_exhibition_by_id', ['id' => $exhibition->getId()])
        ],
        // Groups
        ['groups' => 'get_exhibition_by_id']
        );        


        
    }

    /**
         * Delete an exhibition item
         * @Route("/api/exhibitions/{id<\d+>}/delete", name="api_exhibition_delete", methods={"DELETE"})
         */
        public function deleteExhibition(Exhibition $exhibitionToDelete, EntityManagerInterface $entityManager ) : Response
        {
            $entityManager->remove($exhibitionToDelete);
            $entityManager->flush();

            return $this->json(
        
                [],
                // status code : 204 HTTP_OK        
                Response::HTTP_NO_CONTENT
                // REST ask an header Location + URL 
                
                );
        }

        /**
         * Get exhibitions infos and principal picture for homepage
         * @Route("api/exhibitions/homepage", name="api_exhibitions_homepage", methods={"GET"})
         */
        public function getExhibitionsForHomepage(ExhibitionRepository $exhibitionRepository): Response
        {
            $exhibitionsList = $exhibitionRepository->findAllForHomeSQL();

            return $this->json($exhibitionsList, Response::HTTP_OK, [], ['groups' => 'get_exhibitions_collection']);

        }


        
        /**
         * Get exhibitions by artist for profile page
         * @Route("api/exhibitions/artist/{id<\d+>}/profile", name="api_exhibitions_artist_profile", methods={"GET"})
         */
        public function getExhibitionsForProfile(ExhibitionRepository $exhibitionRepository, User $artist)
        {
            $exhibitionsList = $exhibitionRepository->findTitleAndIdForProfileQB($artist);

            return $this->json($exhibitionsList, Response::HTTP_OK, [], ['groups' => 'get_exhibitions_by_artist']);
        }

        /**
         * Get active exhibitions infos by artist to submit artwork form
         * @Route("api/exhibitions/artist/{id<\d+>}/form", name="api_exhibitions_artist_form", methods={"GET"})
         */
        public function getActiveExhibitionsForArtworkForm(ExhibitionRepository $exhibitionRepository, User $artist)
        {
            $exhibitionsList = $exhibitionRepository->findTitleAndIdForFormSQL($artist);

            return $this->json($exhibitionsList, Response::HTTP_OK, [], ['groups' => 'get_exhibitions_collection']);
        }

        // /**
        //  * Get active exhibitions
        //  *@Route("/api/exhibitions/artist/{id<\d+>}/active", name="api_exhibitions_artist_active", methods={"GET"})
        //  */
        // public function getActiveExhibitionsByArtist(ExhibitionRepository $exhibitionRepository, User $artist)
        // {
        //     $exhibitionsList = $exhibitionRepository->findActiveExhibitionByArtistQB($artist);

        //     return $this->json($exhibitionsList, Response::HTTP_OK, [], ['groups' => 'get_exhibitions_collection']);
        // }
}